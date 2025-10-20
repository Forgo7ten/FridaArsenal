#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
下载 https://github.com/F8LEFT/SoFixer
'''
import os
import sys
import platform
import argparse
import urllib.request
from pathlib import Path

TAG = "v2.1.7"
BASE_URL = f"https://github.com/F8LEFT/SoFixer/releases/download/{TAG}"
DOWNLOAD_URLS = {
    "linux": {
        "32": f"{BASE_URL}/SoFixer-Linux-32",
        "64": f"{BASE_URL}/SoFixer-Linux-64"
    },
    "mac": {
        "32": f"{BASE_URL}/SoFixer-macOS-32",
        "64": f"{BASE_URL}/SoFixer-macOS-64"
    },
    "windows": {
        "32": f"{BASE_URL}/SoFixer-Windows-32.exe",
        "64": f"{BASE_URL}/SoFixer-Windows-64.exe"
    }
}


def detect_system():
    """检测当前系统类型"""
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "darwin":
        return "mac"
    elif system == "windows":
        return "windows"
    else:
        raise ValueError(f"Unsupported system: {system}")


def download_file(url, filename):
    """下载文件"""
    print(f"Downloading: {url}")
    print(f"Save as: {filename}")

    try:
        urllib.request.urlretrieve(url, filename)

        # 给Linux和Mac的文件添加执行权限
        if not filename.endswith('.exe'):
            os.chmod(filename, 0o755)

        print(f"Download completed: {filename}")
        return True
    except Exception as e:
        print(f"Download failed: {e}")
        return False


def download_for_system(system_type):
    """为指定系统下载所有架构的SoFixer"""
    if system_type not in DOWNLOAD_URLS:
        print(f"Unsupported system: {system_type}")
        return False

    success_count = 0
    total_count = len(DOWNLOAD_URLS[system_type])

    for arch, url in DOWNLOAD_URLS[system_type].items():
        filename = os.path.basename(url)
        print(f"Downloading {system_type} {arch}-bit version...")

        if download_file(url, filename):
            success_count += 1

    print(f"{system_type} download summary: {success_count}/{total_count} files downloaded successfully")
    return success_count == total_count


def download_all():
    """下载所有系统的SoFixer"""
    success_count = 0
    total_count = 0

    for system_type in DOWNLOAD_URLS:
        print(f"=== Downloading {system_type} versions ===")
        for arch, url in DOWNLOAD_URLS[system_type].items():
            total_count += 1
            filename = os.path.basename(url)
            print(f"Downloading {system_type} {arch}-bit version...")

            if download_file(url, filename):
                success_count += 1

    print(f"Overall download summary: {success_count}/{total_count} files downloaded successfully")
    return success_count == total_count


def main():
    parser = argparse.ArgumentParser(description='Download SoFixer for different platforms')
    parser.add_argument(
        'system',
        nargs='?',
        choices=['linux', 'mac', 'windows', 'all'],
        help='Target system (linux/mac/windows/all). Auto-detect if not specified.'
    )

    args = parser.parse_args()

    if args.system == 'all':
        print("Downloading SoFixer for all platforms (32-bit and 64-bit)...")
        download_all()
    elif args.system:
        print(f"Downloading SoFixer for {args.system} (32-bit and 64-bit)...")
        download_for_system(args.system)
    else:
        # 自动检测当前系统
        try:
            current_system = detect_system()
            print(f"Detected system: {current_system}")
            print(f"Downloading SoFixer for {current_system} (32-bit and 64-bit)...")
            download_for_system(current_system)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
