#!/usr/bin/env python3
"""
Frida Server 下载工具
用于从 GitHub Release 下载指定版本和架构的 Frida Server

使用示例:
    python download.py -v 17.3.0 -arch android-arm64
    python download.py -v 15.2.2 -arch linux-arm64 -o /tmp/frida-server
    python download.py -v latest -arch android-arm -push
    python download.py --list-arch
"""

import argparse
import os
import sys
import requests
import lzma
import subprocess
import re
from typing import Optional, List, Dict, Tuple, Set
from urllib.parse import urlparse
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    print("警告: tqdm 未安装，将使用简单进度显示")
    print("安装 tqdm: pip install tqdm")
    tqdm = None


class FridaDownloader:
    def __init__(self, version: str, arch: Optional[str] = None, output_path: Optional[str] = None):
        """
        初始化下载器

        Args:
            version: Frida 版本号或 'latest'
            arch: 目标架构（可选，用于列出架构时可以为 None）
            output_path: 输出文件路径（包含文件名）或目录
        """
        self.version = version
        self.arch = arch
        self.base_url = "https://github.com/frida/frida/releases/download"
        self._cached_architectures = None
        self._cached_latest_version = None

        # 处理输出路径
        if output_path:
            self.output_path = Path(output_path)
            # 如果是目录，则在目录下创建默认文件名
            if self.output_path.exists() and self.output_path.is_dir():
                self.output_dir = self.output_path
                self.specified_filename = None
            else:
                # 如果不存在或是文件路径，则分离目录和文件名
                self.output_dir = self.output_path.parent
                self.specified_filename = self.output_path.name
        else:
            self.output_dir = Path(".")
            self.specified_filename = None

        # 创建输出目录
        if arch:  # 只在需要下载时创建目录
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def get_release_info(self, version: str = 'latest') -> Tuple[str, List[str]]:
        """
        获取发布信息，包括版本号和支持的架构

        Args:
            version: 版本号或 'latest'

        Returns:
            (version, architectures) 元组
        """
        # 如果已缓存且请求的是 latest，直接返回缓存
        if version == 'latest' and self._cached_latest_version and self._cached_architectures:
            return self._cached_latest_version, self._cached_architectures

        try:
            if version == 'latest':
                api_url = "https://api.github.com/repos/frida/frida/releases/latest"
                print("正在获取最新版本信息...")
            else:
                # 尝试获取特定版本
                api_url = f"https://api.github.com/repos/frida/frida/releases/tags/{version}"
                print(f"正在获取版本 {version} 信息...")

            response = requests.get(api_url, timeout=10)
            response.raise_for_status()

            data = response.json()
            version_tag = data['tag_name']

            # 去掉版本号前的 'v' (如果有)
            if version_tag.startswith('v'):
                version_tag = version_tag[1:]

            # 从 assets 中提取架构信息
            architectures = self.extract_architectures_from_assets(data.get('assets', []))

            print(f"版本: {version_tag}")
            print(f"找到 {len(architectures)} 个支持的架构")

            # 缓存 latest 版本信息
            if version == 'latest':
                self._cached_latest_version = version_tag
                self._cached_architectures = architectures

            return version_tag, architectures

        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                print(f"错误: 版本 {version} 不存在")
                # 尝试获取最新版本的架构列表作为参考
                if version != 'latest':
                    print("\n尝试获取最新版本的架构列表作为参考...")
                    try:
                        _, latest_archs = self.get_release_info('latest')
                        return version, latest_archs
                    except:
                        pass
            else:
                print(f"获取版本信息失败: HTTP {response.status_code}")
            sys.exit(1)

        except requests.exceptions.RequestException as e:
            print(f"获取版本信息失败: {e}")
            sys.exit(1)

    def extract_architectures_from_assets(self, assets: List[Dict]) -> List[str]:
        """
        从 GitHub Release assets 中提取架构信息

        Args:
            assets: GitHub API 返回的 assets 列表

        Returns:
            架构列表
        """
        architectures = []

        # 匹配 frida-server-{version}-{arch}.xz 或 frida-server-{version}-{arch}.exe.xz
        pattern = re.compile(r'frida-server-[\d\.]+-(.+?)(?:\.exe)?\.xz$')

        for asset in assets:
            name = asset.get('name', '')
            match = pattern.match(name)
            if match:
                arch = match.group(1)
                architectures.append(arch)

        return sorted(architectures)

    def get_supported_architectures(self) -> List[str]:
        """
        获取支持的架构列表

        Returns:
            架构列表
        """
        # 如果版本是 latest，获取最新版本的架构
        if self.version.lower() == 'latest':
            _, architectures = self.get_release_info('latest')
        else:
            # 获取指定版本的架构
            _, architectures = self.get_release_info(self.version)

        return architectures

    def validate_architecture(self, arch: str) -> bool:
        """
        验证架构是否支持

        Args:
            arch: 架构名称

        Returns:
            是否支持
        """
        supported = self.get_supported_architectures()
        return arch in supported

    def build_download_url(self) -> Tuple[str, str]:
        """
        构建下载 URL

        Returns:
            (url, filename) 元组
        """
        # 如果版本是 latest，先获取最新版本号
        if self.version.lower() == 'latest':
            self.version, _ = self.get_release_info('latest')

        # 验证架构
        if not self.validate_architecture(self.arch):
            print(f"\n错误: 架构 '{self.arch}' 在版本 {self.version} 中不受支持")
            self.suggest_alternatives()
            sys.exit(1)

        # Windows 架构需要添加 .exe 后缀
        if self.arch.startswith('windows'):
            filename = f"frida-server-{self.version}-{self.arch}.exe.xz"
        else:
            filename = f"frida-server-{self.version}-{self.arch}.xz"

        url = f"{self.base_url}/{self.version}/{filename}"

        return url, filename

    def download_file(self, url: str, filename: str, chunk_size: int = 8192) -> Path:
        """
        下载文件并显示进度

        Args:
            url: 下载地址
            filename: 原始文件名
            chunk_size: 分块大小

        Returns:
            下载文件的路径
        """
        # 使用指定的文件名或原始文件名
        if self.specified_filename:
            # 如果指定了完整文件名，确保有 .xz 扩展名
            if not self.specified_filename.endswith('.xz'):
                download_filename = f"{self.specified_filename}.xz"
            else:
                download_filename = self.specified_filename
        else:
            download_filename = filename

        filepath = self.output_dir / download_filename

        try:
            print(f"正在下载: {url}")
            print(f"保存到: {filepath}")

            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()

            # 获取文件大小
            total_size = int(response.headers.get('content-length', 0))

            # 使用 tqdm 显示进度（如果可用）
            if tqdm and total_size > 0:
                with open(filepath, 'wb') as f:
                    with tqdm(total=total_size, unit='B', unit_scale=True, desc="下载进度") as pbar:
                        for chunk in response.iter_content(chunk_size=chunk_size):
                            if chunk:
                                f.write(chunk)
                                pbar.update(len(chunk))
            else:
                # 简单进度显示
                downloaded = 0
                with open(filepath, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=chunk_size):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)

                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                print(f"\r下载进度: {progress:.1f}% "
                                      f"({downloaded}/{total_size} bytes)", end='')
                print()  # 换行

            print(f"下载完成: {filepath}")
            return filepath

        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                print(f"\n错误: 文件不存在")
                print(f"URL: {url}")
                self.suggest_alternatives()
            else:
                print(f"\n下载失败: HTTP {response.status_code}")
            sys.exit(1)

        except requests.exceptions.RequestException as e:
            print(f"\n下载失败: {e}")
            sys.exit(1)

    def extract_xz(self, filepath: Path) -> Path:
        """
        解压 .xz 文件

        Args:
            filepath: xz 文件路径

        Returns:
            解压后的文件路径
        """
        # 确定输出文件名
        if self.specified_filename and self.specified_filename.endswith('.xz'):
            # 如果指定的文件名包含 .xz，去掉它
            output_filename = self.specified_filename[:-3]
        elif self.specified_filename:
            # 如果指定了不带 .xz 的文件名，直接使用
            output_filename = self.specified_filename
        else:
            # 使用默认名称（去掉 .xz）
            output_filename = filepath.stem

        output_path = self.output_dir / output_filename

        try:
            print(f"正在解压: {filepath}")

            # 使用 tqdm 显示解压进度（如果可用）
            if tqdm:
                # 获取压缩文件大小用于进度显示
                file_size = filepath.stat().st_size

                with lzma.open(filepath, 'rb') as f_in:
                    # 读取所有数据
                    data = f_in.read()

                with open(output_path, 'wb') as f_out:
                    with tqdm(total=len(data), unit='B', unit_scale=True, desc="解压进度") as pbar:
                        f_out.write(data)
                        pbar.update(len(data))
            else:
                with lzma.open(filepath, 'rb') as f_in:
                    with open(output_path, 'wb') as f_out:
                        f_out.write(f_in.read())

            print(f"解压完成: {output_path}")

            # 设置可执行权限（Unix-like 系统）
            if os.name != 'nt':  # 非 Windows
                os.chmod(output_path, 0o755)
                print(f"已设置可执行权限")

            return output_path

        except Exception as e:
            print(f"解压失败: {e}")
            sys.exit(1)

    def suggest_alternatives(self):
        """建议可能的替代架构"""
        try:
            architectures = self.get_supported_architectures()

            if not architectures:
                print("\n无法获取架构列表")
                return

            print(f"\n版本 {self.version} 支持的架构:")

            # 按平台分组显示
            platforms = {}
            for arch in architectures:
                platform = arch.split('-')[0]
                if platform not in platforms:
                    platforms[platform] = []
                platforms[platform].append(arch)

            for platform, archs in sorted(platforms.items()):
                print(f"\n{platform.upper()}:")
                for arch in sorted(archs):
                    print(f"  - {arch}")

        except Exception as e:
            print(f"\n无法获取架构列表: {e}")

    def push_to_android(self, local_file: Path) -> bool:
        """
        使用 adb push 推送文件到 Android 设备

        Args:
            local_file: 本地文件路径

        Returns:
            是否成功
        """
        try:
            # 检查 adb 是否可用
            result = subprocess.run(['adb', 'version'],
                                    capture_output=True,
                                    text=True,
                                    timeout=5)

            if result.returncode != 0:
                print("错误: adb 命令不可用，请确保已安装 Android SDK")
                return False

            # 检查设备连接
            print("检查 ADB 设备连接...")
            result = subprocess.run(['adb', 'devices'],
                                    capture_output=True,
                                    text=True,
                                    timeout=5)

            if "device" not in result.stdout or result.stdout.count('\n') <= 2:
                print("错误: 没有检测到 Android 设备")
                print("请确保设备已连接并启用了 USB 调试")
                return False

            # 目标路径
            remote_path = f"/data/local/tmp/{local_file.name}"

            # 推送文件
            print(f"正在推送文件到设备...")
            print(f"本地: {local_file}")
            print(f"远程: {remote_path}")

            result = subprocess.run(['adb', 'push', str(local_file), remote_path],
                                    capture_output=True,
                                    text=True,
                                    timeout=30)

            if result.returncode != 0:
                print(f"推送失败: {result.stderr}")
                return False

            print("文件推送成功")

            # 设置执行权限
            print("设置执行权限...")
            result = subprocess.run(['adb', 'shell', 'chmod', '755', remote_path],
                                    capture_output=True,
                                    text=True,
                                    timeout=10)

            if result.returncode != 0:
                print(f"设置权限失败: {result.stderr}")
                return False

            print("权限设置成功")

            # 显示运行命令
            print(f"\n✅ Frida Server 已推送到设备!")
            print(f"\n运行命令:")
            print(f"  adb shell {remote_path}")
            print(f"\n或者以 root 权限运行:")
            print(f"  adb shell su -c {remote_path}")

            return True

        except subprocess.TimeoutExpired:
            print("错误: adb 命令超时")
            return False
        except FileNotFoundError:
            print("错误: 找不到 adb 命令，请确保已安装 Android SDK 并配置了环境变量")
            return False
        except Exception as e:
            print(f"推送失败: {e}")
            return False

    def download(self, extract: bool = True, keep_xz: bool = False, push: bool = False) -> Path:
        """
        执行下载任务

        Args:
            extract: 是否自动解压
            keep_xz: 是否保留 .xz 文件
            push: 是否推送到 Android 设备

        Returns:
            最终文件路径
        """
        # 构建下载 URL
        url, filename = self.build_download_url()

        # 下载文件
        xz_file = self.download_file(url, filename)

        # 解压文件
        final_file = xz_file
        if extract:
            final_file = self.extract_xz(xz_file)

            # 删除原始 xz 文件（如果不保留）
            if not keep_xz:
                xz_file.unlink()
                print(f"已删除压缩文件: {xz_file}")

        # 推送到 Android 设备
        if push:
            if not self.arch.startswith('android'):
                print("\n警告: -push 参数仅适用于 Android 架构")
                response = input("是否仍要推送到设备? (y/N): ")
                if response.lower() != 'y':
                    return final_file

            print("\n" + "=" * 50)
            self.push_to_android(final_file)

        return final_file


def list_architectures(version: str = 'latest'):
    """
    列出指定版本支持的架构

    Args:
        version: 版本号或 'latest'
    """
    downloader = FridaDownloader(version=version)

    try:
        if version == 'latest':
            actual_version, architectures = downloader.get_release_info('latest')
            print(f"\n最新版本 ({actual_version}) 支持的架构:\n")
        else:
            actual_version, architectures = downloader.get_release_info(version)
            print(f"\n版本 {actual_version} 支持的架构:\n")

        if not architectures:
            print("未找到支持的架构")
            return

        # 按平台分组
        platforms = {}
        for arch in architectures:
            platform = arch.split('-')[0]
            if platform not in platforms:
                platforms[platform] = []
            platforms[platform].append(arch)

        # 打印分组列表
        for platform, archs in sorted(platforms.items()):
            print(f"{platform.upper()} ({len(archs)} 个架构):")
            for arch in sorted(archs):
                # 添加特殊标记
                special = ""
                if 'musl' in arch:
                    special = " (musl libc)"
                elif 'be' in arch or 'BE' in arch:
                    special = " (big-endian)"
                elif 'el' in arch:
                    special = " (little-endian)"
                elif arch.endswith('hf'):
                    special = " (hard-float)"
                print(f"  - {arch}{special}")
            print()

        print(f"总计: {len(architectures)} 个架构")

    except Exception as e:
        print(f"获取架构列表失败: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Frida Server 下载工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -v 17.3.0 -arch android-arm64
  %(prog)s -v 15.2.2 -arch linux-arm64 -o /tmp/frida-server
  %(prog)s -v latest -arch android-arm -push
  %(prog)s -v 17.3.0 -arch android-arm64 -o ./my-frida-server
  %(prog)s --list-arch
  %(prog)s --list-arch -v 15.2.2
        """
    )

    parser.add_argument(
        '-v', '--version',
        help='Frida 版本号 (例如: 17.3.0, 15.2.2) 或 "latest" 获取最新版',
        default='latest'
    )

    parser.add_argument(
        '-arch', '--architecture',
        help='目标架构 (例如: android-arm64, linux-x86_64)',
        default='android-arm64'
    )

    parser.add_argument(
        '-o', '--output',
        help='输出文件路径或目录 (默认: 当前目录)',
        default=None
    )

    parser.add_argument(
        '--no-extract',
        action='store_true',
        help='不自动解压 .xz 文件'
    )

    parser.add_argument(
        '--keep-xz',
        action='store_true',
        help='解压后保留 .xz 文件'
    )

    parser.add_argument(
        '-push', '--push',
        action='store_true',
        help='自动推送到 Android 设备的 /data/local/tmp/ 目录'
    )

    parser.add_argument(
        '--list-arch',
        action='store_true',
        help='列出支持的架构（可配合 -v 参数查看特定版本）'
    )

    args = parser.parse_args()

    # 列出架构
    if args.list_arch:
        list_architectures(args.version)
        return

    # 检查必要参数
    if not args.architecture:
        parser.error('需要指定架构 (-arch)，使用 --list-arch 查看支持的架构')

    # 检查 tqdm 安装
    if not tqdm:
        print("提示: 安装 tqdm 可获得更好的进度条显示效果")
        print("      pip install tqdm\n")

    # 创建下载器并执行下载
    downloader = FridaDownloader(
        version=args.version,
        arch=args.architecture,
        output_path=args.output
    )

    try:
        final_file = downloader.download(
            extract=not args.no_extract,
            keep_xz=args.keep_xz,
            push=args.push
        )

        print(f"\n✅ 下载成功!")
        print(f"文件位置: {final_file}")

        # 给出使用提示（如果没有使用 -push）
        if 'android' in args.architecture and not args.push:
            print(f"\n使用提示:")
            print(f"1. 推送到设备: adb push {final_file} /data/local/tmp/")
            print(f"2. 设置权限: adb shell chmod 755 /data/local/tmp/{final_file.name}")
            print(f"3. 运行服务: adb shell /data/local/tmp/{final_file.name}")
            print(f"\n或使用 -push 参数自动推送到设备")

    except KeyboardInterrupt:
        print("\n\n下载已取消")
        sys.exit(1)
    except Exception as e:
        print(f"\n错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
