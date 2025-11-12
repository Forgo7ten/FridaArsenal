import threading
import logging
import sys
import argparse
import os
import signal
from frida_tools.application import Reactor
import frida


def setup_logger():
    """配置日志记录器，同时输出到控制台和文件"""
    logger = logging.getLogger("FridaLoader")
    logger.setLevel(logging.DEBUG)

    # 避免重复添加handler
    if logger.hasHandlers():
        return logger

    # 文件handler
    log_file = "loader.log"
    file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter("%(asctime)s - %(name)s - [%(levelname)s] - %(message)s")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # 控制台handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(asctime)s - [%(levelname)s] - %(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    return logger


def parse_arguments():
    """解析命令行参数，模仿frida-tools的参数风格"""
    parser = argparse.ArgumentParser(
        description="Advanced Frida Loader.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # 设备选择参数组（互斥）
    device_group = parser.add_mutually_exclusive_group()
    device_group.add_argument("-U", "--usb", action="store_true", help="connect to USB device (default)")
    device_group.add_argument("-R", "--remote", action="store_true", help="connect to remote frida-server")
    device_group.add_argument("-H", "--host", type=str, help="connect to remote frida-server on HOST")

    # 目标选择参数组（互斥且必选）
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-f", "--file", dest="target_file", help="spawn FILE")
    target_group.add_argument("-F", "--attach-frontmost", action="store_true", help="attach to frontmost application")
    target_group.add_argument("-n", "--attach-name", dest="target_name", help="attach to NAME")
    target_group.add_argument("-p", "--attach-pid", dest="target_pid", type=int, help="attach to PID")

    # 脚本文件参数
    parser.add_argument("-l", "--load", dest="script", default="_agent.js", help="load SCRIPT (default: _agent.js)")

    return parser.parse_args()


# 初始化全局logger
logger = setup_logger()


class Application:
    def __init__(self, args):
        self.args = args  # 保存命令行参数

        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda reactor: self._stop_requested.wait())

        self._device = None
        self._sessions = {}
        self.main_pid = None  # 记录主进程PID
        self.user_script_content = ""  # 存储用户脚本内容

    def run(self):
        try:
            self._reactor.schedule(lambda: self._start())
            self._reactor.run()
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}", exc_info=True)
            self.stop()
        finally:
            logger.info("Cleaning up and exiting.")
            self._cleanup()

    def stop(self):
        """停止应用程序并清理资源"""
        logger.info("Stopping application...")
        self._stop_requested.set()

    def _cleanup(self):
        """清理所有资源"""
        # 分离所有session
        for pid, session_info in list(self._sessions.items()):
            try:
                session_info['session'].detach()
                logger.debug(f"Detached session for PID {pid}")
            except frida.InvalidOperationError:
                logger.debug(f"Session for PID {pid} was already detached")
            except Exception as e:
                logger.warning(f"Error detaching session for PID {pid}: {e}")

        # 清空sessions字典
        self._sessions.clear()
        logger.info("Cleanup completed.")

    def _get_device(self):
        """根据命令行参数连接到对应的Frida设备"""
        logger.debug("Connecting to Frida device...")

        if self.args.remote:
            # 连接到远程frida-server（默认端口）
            self._device = frida.get_remote_device()
            logger.debug("Connected to remote device")
        elif self.args.host:
            # 连接到指定HOST的frida-server
            self._device = frida.get_device_manager().add_remote_device(self.args.host)
            logger.debug(f"Connected to remote device at {self.args.host}")
        else:
            # 默认连接USB设备
            self._device = frida.get_usb_device(timeout=5)
            logger.debug(f"Connected to USB device: {self._device.name}")

    def _load_user_script_content(self):
        """从文件加载用户脚本内容"""
        script_path = self.args.script

        # 检查脚本文件是否存在
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Script file not found: {script_path}")

        logger.info(f"Loading script from '{script_path}'...")

        # 读取脚本文件内容
        with open(script_path, "r", encoding="utf-8") as f:
            self.user_script_content = f.read()

        logger.info(f"Script loaded successfully.")

    def _setup_device_callbacks(self):
        """设置设备级别的回调函数"""
        logger.info("Setting up device-wide callbacks...")

        # spawn gating（拦截新进程创建） 设备上所有新进程创建
        # self._device.enable_spawn_gating()
        # self._device.on("spawn-added", lambda spawn: self._reactor.schedule(lambda: self._on_spawn_added(spawn)))
        # self._device.on("spawn-removed", lambda spawn: self._reactor.schedule(lambda: self._on_spawn_removed(spawn)))

        # 监听child事件（子进程创建）
        self._device.on("child-added", lambda child: self._reactor.schedule(lambda: self._on_child_added(child)))
        self._device.on("child-removed", lambda child: self._reactor.schedule(lambda: self._on_child_removed(child)))

        # 监听进程崩溃事件
        self._device.on("process-crashed",
                        lambda crash: self._reactor.schedule(lambda: self._on_process_crashed(crash)))

        # 监听进程输出
        self._device.on("output", lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data)))

    def _start(self):
        """启动主流程：连接设备、选择目标、注入脚本"""
        # 1. 连接设备
        self._get_device()

        # 2. 加载用户脚本
        self._load_user_script_content()

        # 3. 设置设备回调
        self._setup_device_callbacks()

        # 4. 根据参数选择目标并注入
        if self.args.target_file:
            # spawn模式：启动新进程
            self.spwan_and_instrument()
        else:
            # attach模式：附加到现有进程
            self.attach_and_instrument()
        if self.main_pid and self.main_pid in self._sessions:
            logger.info("Frida loader is running. Press Ctrl+C to exit.")

    def spwan_and_instrument(self):
        logger.info(f"Spawning '{self.args.target_file}'...")
        pid = self._device.spawn([self.args.target_file])
        self.main_pid = pid
        self._instrument(pid, need_resume=True)

    def attach_and_instrument(self):
        pid = None
        if self.args.attach_frontmost:
            # 附加到前台应用
            app = self._device.get_frontmost_application()
            if not app:
                raise frida.ProcessNotFoundError("No frontmost application found.")
            pid = app.pid
            logger.info(f"Attaching to frontmost application: {app.name} (PID: {pid})")
        elif self.args.target_name:
            # 附加到指定进程名
            process = self._device.get_process(self.args.target_name)
            pid = process.pid
            logger.info(f"Attaching to application name: {pid}")
        elif self.args.target_pid:
            # 附加到指定PID
            pid = self.args.target_pid
            logger.info(f"Attaching to PID: {pid}")
        self.main_pid = pid
        self._instrument(pid)

    def _stop_if_idle(self):
        if len(self._sessions.keys()) == 0:
            logger.info("All sessions closed, stopping application...")
            self._stop_requested.set()

    def _instrument(self, pid, need_resume=False):
        """向目标进程注入脚本"""
        logger.info(f"Attaching to PID: {pid}")
        session = self._device.attach(pid)
        session.on("detached", lambda reason: self._reactor.schedule(lambda: self._on_detached(pid, session, reason)))
        logger.debug("Enabling child gating")
        session.enable_child_gating()
        logger.debug("Creating script")
        # 使用加载的用户脚本内容，而不是硬编码的脚本
        script = session.create_script(self.user_script_content)
        script.on("message", lambda message, data: self._reactor.schedule(lambda: self._on_message(pid, message)))
        logger.debug("Loading script")
        script.load()
        self._sessions[pid] = {'pid': pid, 'session': session, 'script': script}
        logger.info(f"Script injected and loaded into process PID: {pid}")

        if need_resume:
            logger.info(f"Resuming PID: {pid}")
            self._device.resume(pid)

    def _on_spawn_added(self, spawn):
        """当新进程被spawn但尚未启动时触发"""
        logger.info(f"[DEVICE EVENT] Spawn added: {spawn.identifier} (PID: {spawn.pid})")

    def _on_spawn_removed(self, spawn):
        """当spawn的进程被移除时触发"""
        logger.info(f"[DEVICE EVENT] Spawn removed: {spawn.identifier} (PID: {spawn.pid})")

    def _on_child_added(self, child):
        """当子进程被创建时触发（需要enable_child_gating）"""
        logger.info(f"[DEVICE EVENT] Child added (gated): {child.identifier} (PID: {child.pid})")
        try:
            self._instrument(child.pid, need_resume=True)
        except Exception as e:
            logger.error(f"Failed to instrument child {child.pid}: {e}")
            # 即使失败也要恢复子进程，避免阻塞
            try:
                self._device.resume(child.pid)
            except Exception as e:
                logger.error(f"Error resuming child {child.pid}: {e}")

    def _on_child_removed(self, child):
        """当子进程被移除时触发"""
        logger.info(f"[DEVICE EVENT] Child removed: {child.identifier} (PID: {child.pid})")

    def _on_process_crashed(self, crash):
        """当进程崩溃时触发"""
        logger.error(
            f"[DEVICE EVENT] Process crashed: PID={crash.pid}, Name={crash.process_name}\n"
            f"Crash Report:\n{crash.report}"
        )
        # 如果主进程崩溃，停止应用
        if self.main_pid and crash.pid == self.main_pid:
            logger.error("Main process crashed, stopping application...")
            self._stop_requested.set()

    def _on_output(self, pid, fd, data):
        """处理进程输出，fd=1是stdout，fd=2是stderr"""
        if data:
            # 根据文件描述符选择日志级别
            log_level = logging.INFO if fd == 1 else logging.WARNING
            decoded_data = data.decode('utf-8', errors='ignore').strip()
            logger.log(log_level, f"[PROCESS OUTPUT pid={pid}] {decoded_data}")

    def _on_detached(self, pid, session, reason):
        """当session断开时触发"""
        logger.info(f"[SESSION EVENT] Detached from PID {pid}, reason: '{reason}'")
        if pid in self._sessions:
            del self._sessions[pid]

        # 检查是否是主进程断开
        if hasattr(self, 'main_pid') and pid == self.main_pid:
            logger.warning("Main process has detached.")
            self.main_pid = None
            self._stop_requested.set()
        else:
            self._reactor.schedule(self._stop_if_idle, delay=0.5)

    def _on_message(self, pid, message):
        """处理来自Frida脚本的消息"""
        if message['type'] == 'send':
            logger.info(f"[AGENT] PID {pid}: {message['payload']}")
        elif message['type'] == 'error':
            stack = message.get('stack', 'No stack trace available')
            logger.error(f"[AGENT ERROR] PID {pid}: {message['description']}\n{stack}")
        else:
            logger.warning(f"[AGENT] PID {pid} unknown message type: {message}")


# 主程序入口
if __name__ == "__main__":
    # 创建全局应用实例引用，用于信号处理
    app_instance = None


    def signal_handler(sig, frame):
        """处理Ctrl+C信号"""
        logger.info("Ctrl+C pressed. Shutting down gracefully...")
        if app_instance:
            app_instance.stop()


    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)

    try:
        args = parse_arguments()
        app = Application(args)
        app_instance = app
        app.run()
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
    finally:
        logger.info("Loader has terminated.")
