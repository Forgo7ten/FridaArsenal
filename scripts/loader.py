#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import select
from typing import List
import frida
import argparse
import logging
import os
import signal
from threading import Event
import sys

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("未检测到 watchdog 库，请先安装：pip install watchdog")
    sys.exit(1)


### 初始化日志
def setup_logger():
    """Configures the logger to output to both console and a file."""
    logger = logging.getLogger("FridaLoader")
    logger.setLevel(logging.DEBUG)
    if logger.hasHandlers():
        return logger
    log_file = "loader.log"
    file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter("%(asctime)s - %(name)s - [%(levelname)s] - %(message)s")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(asctime)s - [%(levelname)s] - %(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    return logger


### 参数解析
def parse_arguments():
    """Parses command-line arguments, mimicking frida-tools."""
    parser = argparse.ArgumentParser(
        description="Advanced Frida Loader with REPL, Hot-Reload, and RPC Merging.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    device_group = parser.add_mutually_exclusive_group()
    device_group.add_argument("-U", "--usb", action="store_true", help="connect to USB device (default)")
    device_group.add_argument("-R", "--remote", action="store_true", help="connect to remote frida-server")
    device_group.add_argument("-H", "--host", type=str, help="connect to remote frida-server on HOST")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-f", "--file", dest="target_file", help="spawn FILE")
    target_group.add_argument("-F", "--attach-frontmost", action="store_true", help="attach to frontmost application")
    target_group.add_argument("-n", "--attach-name", dest="target_name", help="attach to NAME")
    target_group.add_argument("-p", "--attach-pid", dest="target_pid", type=int, help="attach to PID")
    parser.add_argument("-l", "--load", dest="script", default="_agent.js", help="load SCRIPT (default: _agent.js)")
    return parser.parse_args()


class ScriptChangeHandler(FileSystemEventHandler):
    """Triggers a script reload upon detecting a file modification."""

    def __init__(self, app_instance):
        super().__init__()
        self.app = app_instance
        self.script_to_watch = os.path.abspath(self.app.args.script)

    def on_modified(self, event):
        """Called when a file or directory is modified."""
        if event.is_directory:
            return

        if os.path.abspath(event.src_path) == self.script_to_watch:
            self.app.logger.info(
                f"Watchdog detected modification in '{os.path.basename(self.script_to_watch)}'. Triggering reload.")
            self.app.reload_script()


class Application:
    """The core application class that manages Frida interactions."""

    # This JS scaffolding captures the user's RPC exports and merges them with its own.
    AGENT_TEMPLATE = """
    'use strict';
    const loader_rpc_exports = {{
        eval: function (command) {{
            let result;
            try {{
                result = (new Function('return ' + command))();
                if (result === undefined) return "undefined";
                if (result === null) return "null";
                if (typeof result === 'object' && result !== null && result.$h) {{
                    return result.toString();
                }}
                if (typeof result === 'object' && result !== null && result.$className) {{
                    return `[Java Class: ${{result.$className}}]`;
                }}
                return JSON.stringify(result, null, 2);
            }} catch (e) {{
                return `Error: ${{e.message}}\\nStack: ${{e.stack}}`;
            }}
        }}
    }};

    const rpc_for_user_script = {{ exports: {{}} }};

    (function(rpc) {{
        try {{
            {user_script}
        }} catch (e) {{
            console.error("FridaLoader: Error executing user script. " + e + "\\nStack: " + e.stack);
        }}
    }})(rpc_for_user_script);

    const user_rpc_exports = rpc_for_user_script.exports;

    const final_exports = Object.assign({{}}, loader_rpc_exports, user_rpc_exports);
    rpc.exports = final_exports;
    console.log("Final rpc.exports keys: " + JSON.stringify(Object.keys(rpc.exports)));
    """

    def __init__(self, args, logger):
        self.args = args
        self.logger = logger
        self.device = None
        self.sessions = {}
        self.main_pid = None
        self.user_script_content = ""
        self.script_mtime = 0
        self.exit_event = Event()
        self.observer = None

    def _build_final_script(self):
        """Injects the user's script into the agent template."""
        return self.AGENT_TEMPLATE.format(user_script=self.user_script_content)

    def run(self):
        try:
            self._get_device()
            self._setup_device_callbacks()
            self._start_instrumentation()
            if self.main_pid and self.main_pid in self.sessions:
                self._start_background_tasks()
                self.logger.info("Frida loader is running. Type 'exit' or 'quit' in REPL to exit.")
                self._run_repl()
        except frida.ProcessNotFoundError as e:
            self.logger.error(f"Process not found: {e}")
        except frida.ServerNotRunningError:
            self.logger.error("Frida server is not running on the device. Please start it with './frida-server'")
        except frida.TransportError as e:
            self.logger.error(f"Connection to Frida server lost: {e}")
        except FileNotFoundError as e:
            self.logger.error(e)
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        finally:
            self.logger.info("Cleaning up and exiting.")
            self.stop()
            if self.main_pid and self.main_pid in self.sessions:
                try:
                    self.sessions[self.main_pid]["session"].detach()
                    self.logger.info("Session detached successfully.")
                except frida.InvalidOperationError:
                    self.logger.warning("Session was already detached or invalid.")
                    pass

    def _get_device(self):
        self.logger.debug("Connecting to Frida device...")
        if self.args.remote:
            self.device = frida.get_remote_device()
        elif self.args.host:
            self.device = frida.get_device_manager().add_remote_device(self.args.host)
        else:
            self.device = frida.get_usb_device(timeout=5)
        self.logger.debug(f"Successfully connected to device: {self.device.name}")

    def _load_user_script_content(self):
        script_path = self.args.script
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Script file not found: {script_path}")
        mtime = os.path.getmtime(script_path)
        if mtime != self.script_mtime:
            self.logger.info(f"Script '{script_path}' has changed.")
            with open(script_path, "r", encoding="utf-8") as f:
                self.user_script_content = f.read()
            self.script_mtime = mtime
            return True
        return False

    def _setup_device_callbacks(self):
        self.logger.info("Setting up device-wide callbacks...")
        self.device.on("spawn-added", self._on_spawn_added)
        self.device.on("spawn-removed", self._on_spawn_removed)
        self.device.on("child-added", self._on_child_added)
        self.device.on("child-removed", self._on_child_removed)
        self.device.on("process-crashed", self._on_process_crashed)
        self.device.on("output", self._on_output)

    def _start_instrumentation(self):
        target_id, pid = None, None
        session: frida.core.Session = None
        if self.args.target_file:
            self.logger.info(f"Spawning '{self.args.target_file}' with child gating enabled...")
            pid = self.device.spawn([self.args.target_file])
            session = self.device.attach(pid)
            session.enable_child_gating()
        else:
            if self.args.attach_frontmost:
                app = self.device.get_frontmost_application()
                if not app: raise frida.ProcessNotFoundError("No frontmost application found.")
                target_id = app.pid
                self.logger.info(f"Attaching to frontmost application: {app.name} (PID: {target_id})")
            elif self.args.target_name:
                target_id = self.args.target_name
                self.logger.info(f"Attaching to application name: {target_id}")
            elif self.args.target_pid:
                target_id = self.args.target_pid
                self.logger.info(f"Attaching to PID: {target_id}")
            session = self.device.attach(target_id)
        pid = session._impl.pid
        self.main_pid = pid
        self.logger.info(f"Successfully attached to main process PID: {pid}. Injecting script...")

        session.on("detached", self._make_detached_handler(pid))
        self._load_user_script_content()
        final_script = self._build_final_script()
        script = session.create_script(final_script)
        script.on("message", self._on_message)
        script.load()
        self.sessions[pid] = {'session': session, 'script': script}
        logger.info("Script injected and loaded into main process.")
        if self.args.target_file:
            self.device.resume(pid)
            self.logger.info(f"Resumed PID: {pid}")

    def reload_script(self):
        if self._load_user_script_content():
            final_script = self._build_final_script()
            for pid, session_info in self.sessions.items():
                session = session_info['session']
                script = session_info['script']
                if script.is_destroyed:
                    self.logger.warning(f"Session for PID {pid} is detached. Skipping reload.")
                    continue
                try:
                    if not session.is_detached and not script.is_destroyed:
                        script.unload()
                        new_script = session.create_script(final_script)
                        new_script.on("message", self._on_message)
                        new_script.load()
                        self.sessions[pid]["script"] = new_script
                        self.logger.info(f"Script reloaded successfully for PID: {pid}")
                except frida.InvalidOperationError:
                    self.logger.warning(f"Script for PID {pid} was already unloaded or invalid.")
                    self._on_detached(pid, "invalid_operation")
                except Exception as e:
                    self.logger.error(f"Failed to reload script for PID {pid}: {e}")

    def _start_background_tasks(self):
        script_path = self.args.script
        if not os.path.exists(script_path):
            self.logger.warning(f"Script file '{script_path}' not found. Hot-reload disabled.")
            return
        event_handler = ScriptChangeHandler(self)
        self.observer = Observer()
        watch_path = os.path.dirname(os.path.abspath(script_path)) or '.'
        self.observer.schedule(event_handler, watch_path, recursive=False)
        self.observer.start()
        self.logger.info(f"Watchdog hot-reload monitor started for '{script_path}' in '{watch_path}'.")

    def _run_repl(self):
        while not self.exit_event.is_set():
            try:
                if not select.select([sys.stdin], [], [], 1)[0]:
                    continue
                command = input(">>> ")
                if command.lower().strip() in ["exit", "quit"]: break
                if not command.strip(): continue
                if self.main_pid and self.main_pid in self.sessions:
                    main_script = self.sessions[self.main_pid]['script']
                    if main_script and not main_script.is_destroyed:
                        result = main_script.exports.eval(command)
                        print(f"{result}\n")
                    else:
                        self.logger.warning("Main script is not loaded or destroyed. Cannot execute command.")
                else:
                    self.logger.warning("Main process not attached or has exited. REPL is disabled.")
            except frida.core.RPCException as e:
                self.logger.error(f"REPL RPC Error: {e}")
            except Exception as e:
                self.logger.error(f"REPL Error: {e}")
                break
        self.stop()

    def _on_message(self, message, data):
        if message['type'] == 'send':
            self.logger.info(f"[AGENT] {message['payload']}")
        elif message['type'] == 'error':
            stack = message.get('stack', 'No stack trace available')
            self.logger.error(f"[AGENT ERROR] {message['description']}\n{stack}")
        else:
            self.logger.warning(f"[AGENT UNKNOWN MSG] {message}")

    def _on_child_added(self, child):
        self.logger.info(f"[DEVICE EVENT] Child added (gated): {child.identifier} (PID: {child.pid})")
        try:
            child_session = self.device.attach(child.pid)
            child_session.on("detached", self._make_detached_handler(child.pid))
            self._load_user_script_content()
            final_script = self._build_final_script()
            child_script = child_session.create_script(final_script)
            child_script.on('message', self._on_message)
            child_script.load()
            self.sessions[child.pid] = {'session': child_session, 'script': child_script}
            self.logger.info(f"Successfully attached and injected script into child PID: {child.pid}")
        except Exception as e:
            self.logger.error(f"Failed to instrument child process {child.pid}: {e}")
        finally:
            try:
                self.device.resume(child.pid)
            except frida.NotSupportedError:
                self.logger.warning(f"Failed to resume child process {child.pid}.")

    def _make_detached_handler(self, pid):
        def on_detached(reason):
            self._on_detached(pid, reason)

        return on_detached

    def _on_detached(self, pid, reason):
        self.logger.info(f"[SESSION EVENT] Session for PID {pid} detached. Reason: {reason}.")
        if pid in self.sessions:
            del self.sessions[pid]
            self.logger.info(f"Cleaned up session for PID {pid} from tracking.")
        if pid == self.main_pid:
            self.logger.warning("Main process has detached. REPL will no longer work.")
            self.main_pid = None
            self.stop()

    def _on_spawn_added(self, spawn):
        self.logger.info(f"[DEVICE EVENT] Spawn added: {spawn.identifier} (PID: {spawn.pid})")

    def _on_spawn_removed(self, spawn):
        self.logger.info(f"[DEVICE EVENT] Spawn removed: {spawn.identifier} (PID: {spawn.pid})")

    def _on_child_removed(self, child):
        self.logger.info(f"[DEVICE EVENT] Child removed: {child.identifier} (PID: {child.pid})")

    def _on_process_crashed(self, crash):
        self.logger.error(
            f"[DEVICE EVENT] Process crashed: PID={crash.pid}, Name={crash.process_name}\nCrash Report:\n{crash.report}")
        self.stop()

    def _on_output(self, pid, fd, data):
        if data:
            log_level = logging.INFO if fd == 1 else logging.WARNING
            self.logger.log(log_level, f"[PROCESS OUTPUT pid={pid}] {data.decode('utf-8', errors='ignore').strip()}")

    def stop(self):
        self.exit_event.set()
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            self.logger.debug("Watchdog observer stopped.")
        try:
            sys.stdin.close()
        except Exception:
            pass


# ===================================================================
# 4. 主程序入口
# ===================================================================
if __name__ == "__main__":
    logger = setup_logger()
    app_instance: List[Application] = [None]


    def signal_handler(sig, frame):
        logger.info("Ctrl+C pressed. Shutting down.")
        if app_instance[0]: app_instance[0].stop()


    signal.signal(signal.SIGINT, signal_handler)
    try:
        args = parse_arguments()
        app = Application(args, logger)
        app_instance[0] = app
        app.run()
    except frida.InvalidArgumentError as e:
        logger.error(f"Argument Error: {e}. Please check your target specifier.")
    except frida.NotSupportedError:
        logger.error(
            "Operation not supported. Your Frida version might be incompatible or the device doesn't support this feature.")
    except Exception as e:
        logger.critical(f"A critical error occurred in the main block: {e}", exc_info=True)
    finally:
        logger.info("Loader has terminated.")
