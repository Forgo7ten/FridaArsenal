#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import time

import frida

# JS脚本（暂时为空）
JS_TEMPLATE = """
function dump_so(so_name) {
    const module = Process.findModuleByName(so_name);
    if (!module) {
        send({type: 'error', message: 'Module not found: ' + so_name});
        return;
    }
    const module_size = module.size;
    Memory.protect(ptr(module.base), module_size, 'rwx');
    const soMemory = Memory.readByteArray(module.base, module_size);
    send({name: so_name, base: module.base, size: module_size}, soMemory);
}

dump_so("%s")
"""


class Application:
    def __init__(self, target, so_name, is_spawn, host):
        self.target = target
        self.so_name = so_name
        self.js_code = JS_TEMPLATE % so_name
        self.is_spawn = is_spawn
        self.host = host
        self.device = None
        self.session = None
        self.script = None
        self.done = False

    def get_device(self):
        """获取Frida设备"""
        if self.host:
            self.device = frida.get_device_manager().add_remote_device(self.host)
        else:
            self.device = frida.get_usb_device()
        return self.device

    def attach_target(self):
        """附加到目标进程"""
        if self.is_spawn:
            # Spawn模式
            pid = self.device.spawn([self.target])
            self.session = self.device.attach(pid)
            self.device.resume(pid)
        else:
            # Attach模式
            if self.target.isdigit():
                pid = int(self.target)
            else:
                pid = self.target
            self.session = self.device.attach(pid)
        return self.session

    def on_message(self, message, data):
        """处理Frida消息"""
        if message['type'] == 'send':
            payload = message['payload']
            if payload.get('type') == 'error':
                print(f"Error: {payload['message']}")
                self.done = True
                return
            so_name = payload['name']
            base_address = payload['base']
            size = payload['size']

            print(f"Dumping {so_name} (Base: {base_address}, Size: {size})")

            # 保存dump的.so文件
            with open(so_name, "wb") as f:
                f.write(data)
            print(f"{so_name} dumped successfully!")
            self.done = True
        else:
            print(f"Error: {message}")
            self.done = True

    def create_script(self):
        """创建并加载脚本"""
        self.script = self.session.create_script(self.js_code)
        self.script.on('message', self.on_message)
        self.script.load()
        return self.script

    def run(self):
        print(f"> Target: {self.target}")
        print(f"> dump so: {self.so_name}")
        print(f"> Mode: {'Spawn' if self.is_spawn else 'Attach'}")
        print(f"> Device: {self.host if self.host else 'USB'}")
        try:
            self.get_device()
            self.attach_target()
            print(" Dumping in progress...")
            self.create_script()
            while not self.done:
                time.sleep(1)
        except KeyboardInterrupt:
            print(" User interrupted")
        except Exception as e:
            print(f"Runtime error: {e}")
        finally:
            if self.script:
                self.script.unload()
            if self.session:
                self.session.detach()
            # print("Cleanup complete")
            pass


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='Frida SO Dumper')
    parser.add_argument('-f', '--spawn', action='store_true', help='Spawn mode')
    parser.add_argument('-H', '--host', help='Remote frida-server (ip:port)')
    parser.add_argument('target', help='Package name or PID')
    parser.add_argument('so_name', help='SO file name to dump')

    return parser.parse_args()


def main():
    # 1. 解析参数
    args = parse_args()

    # 2. 创建Dumper实例
    application = Application(args.target, args.so_name, args.spawn, args.host)

    application.run()


if __name__ == "__main__":
    main()
