import concurrent.futures
import ctypes
import hashlib
import json
import os
import queue
import re
import struct
import subprocess
import threading
import time
import tkinter as tk
import warnings
from ctypes import wintypes
from tkinter import scrolledtext, filedialog, ttk, messagebox

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Padding as AesPadding
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

# 忽略libpng警告
warnings.filterwarnings("ignore", category=UserWarning)

# ==========================================================================
# 微信 4.x dat 格式常量
#   微信 4.x 图片 .dat 结构（参考 WeChatDataAnalysis 项目）：
#   [15字节头][AES-ECB加密段][固定16字节标记][单字节XOR段]
#   15字节头 = 签名(6) + aes_size(4,LE) + xor_size(4,LE) + 填充(1)
#
#   注意：AES 段与 XOR 段之间夹着一个固定 16 字节的常量标记
#   （e8f45b657f6d049de701465372f40b47），它并非图片数据。
#   实测 500 个文件该段内容完全一致，若把它当作明文拼进图片会导致
#   扫描数据错位、解码后出现偏色（红/黄/蓝等单通道异常）。重构时应跳过。
# ==========================================================================
SIG_V1 = b"\x07\x08V1\x08\x07"          # V1：AES密钥硬编码常量
SIG_V2 = b"\x07\x08V2\x08\x07"          # V2：AES密钥为账号密钥（需从微信提取/缓存）
# V1 的 AES 密钥是硬编码常量 = md5("0") 的前 16 字节
V1_AES_KEY = b"cfcd208495d565ef"
AES_BLOCK = 16
# 微信 4.x 在 AES 段与 XOR 段之间嵌入的固定 16 字节标记（非图片数据）
V4_RAW_MARKER = bytes.fromhex("e8f45b657f6d049de701465372f40b47")


class WxChatImgRevert:
    def __init__(self):
        # 文件类型标识映射（十六进制签名到文件扩展名）
        self.FILE_TYPE_MAP = {
            "ffd8ffe000104a464946": "jpg",
            "89504e470d0a1a0a0000": "png",
            "47494638396126026f01": "gif",
            "49492a00227105008037": "tif",
            "424d228c010000000000": "bmp",
            "424d8240090000000000": "bmp",
            "424d8e1b030000000000": "bmp",
            "41433130313500000000": "dwg",
            "3c21444f435459504520": "html",
            "3c21646f637479706520": "htm",
            "48544d4c207b0d0a0942": "css",
            "696b2e71623d696b2e71": "js",
            "7b5c727466315c616e73": "rtf",
            "38425053000100000000": "psd",
            "46726f6d3a203d3f6762": "eml",
            "d0cf11e0a1b11ae10000": "doc",
            "5374616E64617264204A": "mdb",
            "252150532D41646F6265": "ps",
            "255044462d312e360d25": "pdf",
            "2e524d46000000120001": "rmvb",
            "464c5601050000000900": "flv",
            "00000020667479706973": "mp4",
            "49443303000000000f76": "mp3",
            "000001ba210001000180": "mpg",
            "3026b2758e66cf11a6d9": "wmv",
            "524946464694c9015741": "wav",
            "52494646d07d60074156": "avi",
            "4d546864000000060001": "mid",
            "504b0304140000000800": "zip",
            "526172211a0700cf9073": "rar",
            "235468697320636f6e66": "ini",
            "504b03040a0000000000": "jar",
            "4d5a9000030000000400": "exe",
            "3c25402070616765206c": "jsp",
            "4d616e69666573742d56": "mf",
            "3c3f786d6c2076657273": "xml",
            "efbbbf2f2a0d0a53514c": "sql",
            "7061636b616765207765": "java",
            "406563686f206f66660d": "bat",
            "1f8b0800000000000000": "gz",
            "6c6f67346a2e726f6f74": "properties",
            "cafebabe0000002e0041": "class",
            "49545346030000006000": "chm",
            "04000000010000001300": "mxp",
            "504b0304140006000800": "docx",
            "6431303a637265617465": "torrent",
            "494d4b48010100000200": "264",
            "6D6F6F76": "mov",
            "FF575043": "wpd",
            "CFAD12FEC5FD746F": "dbx",
            "2142444E": "pst",
            "AC9EBD8F": "qdf",
            "E3828596": "pwl",
            "2E7261FD": "ram"
        }
        self.running = False
        self.message_queue = queue.Queue()
        self.processed_files = 0
        self.total_files = 0
        self.should_stop = False
        self._count_lock = threading.Lock()  # 保护 processed_files 的线程安全递增

    def convert(self, path, target_path, gui=None):
        """
        转换加密的微信图像为原始格式

        Args:
            path: 包含加密文件的源路径
            target_path: 保存解密文件的目标目录
            gui: 可选的GUI对象，用于显示进度和控制处理
        """
        self.should_stop = False
        self.processed_files = 0
        self.message_queue = queue.Queue()

        # 启动一个后台线程进行转换
        thread = threading.Thread(target=self._convert_thread, args=(path, target_path, gui))
        thread.daemon = True
        thread.start()

        # 更新GUI的消息处理
        if gui:
            self.running = True
            gui.root.after(100, lambda: self._process_messages(gui))

        return thread

    def _convert_thread(self, path, target_path, gui):
        """在后台线程中处理转换逻辑"""
        try:
            source_file = os.path.abspath(path)

            # 检查源是否为单个文件
            if os.path.isfile(source_file):
                self.total_files = 1
                self._update_gui("正在处理单个文件...", gui)
                self.parse_file(source_file, target_path, 0, gui)
                self._update_gui("\n解密完成！", gui)
                return

            # 获取目录中的所有文件
            all_files = []
            self._scan_directory(path, all_files)

            if not all_files:
                self._update_gui("\n在目录中未发现文件。", gui)
                return

            self.total_files = len(all_files)
            self._update_gui(f"总共发现 {self.total_files} 个文件", gui)

            # 从第一个有效文件中找到XOR密钥（V3），并检测是否存在 V2 文件
            xor_key = 0
            has_v2 = False
            for file_path in all_files[:50]:  # 只检查前50个文件以提高速度
                if self.should_stop:
                    self._update_gui("\n操作已取消。", gui)
                    return
                if not os.path.isfile(file_path):
                    continue
                try:
                    with open(file_path, 'rb') as f:
                        head = f.read(6)
                    if head == SIG_V2:
                        has_v2 = True
                        continue
                    if not xor_key:
                        xor_info = self.get_xor(file_path)
                        if xor_info and xor_info[1] is not None:
                            xor_key = xor_info[1]
                except Exception:
                    continue
            if xor_key:
                self._update_gui(f"找到V3 XOR密钥: {xor_key}", gui)

            # 若存在 V2 文件，准备账号 AES 密钥（缓存 -> 界面输入 -> 从微信进程提取）
            self._pending_v2_aes = None
            self._pending_v2_xor = None  # 账号默认 XOR 密钥（V2 文件夹无 V3 可推导时作为回退）
            if has_v2:
                account = self._extract_account_from_path(path)
                aes, cached_xk = self._get_cached_key(account)
                if not aes:
                    # 账号无法从路径识别时，遍历缓存密钥并用模板校验
                    f_account, f_aes, f_xk = self._find_valid_cached_key(path)
                    if f_aes:
                        account = f_account or account
                        aes = f_aes
                        cached_xk = f_xk
                if aes:
                    self._pending_v2_aes = aes
                    self._pending_v2_xor = cached_xk
                    self._update_gui(f"使用缓存账号密钥: {account}", gui)
                else:
                    gui_aes = ""
                    if gui:
                        try:
                            gui_aes = (gui.aes_entry.get() or "").strip()
                        except Exception:
                            gui_aes = ""
                    if gui_aes and len(gui_aes) >= 16:
                        self._pending_v2_aes = gui_aes[:16]
                        self._update_gui("使用界面输入的账号AES密钥", gui)
                    else:
                        self._update_gui("检测到微信4.x V2 文件，正在从微信进程提取账号密钥...", gui)
                        result = self.extract_key_from_wechat(path, gui)
                        if result:
                            self._pending_v2_aes, xk = result
                            self._pending_v2_xor = xk
                            self._save_cached_keys(account, self._pending_v2_aes, xk)
                            self._update_gui(f"已提取账号密钥并缓存: {self._pending_v2_aes}", gui)
                            if gui:
                                try:
                                    gui.aes_entry.delete(0, tk.END)
                                    gui.aes_entry.insert(0, self._pending_v2_aes)
                                    gui.key_status.config(text=f"已提取 (xor={xk})")
                                except Exception:
                                    pass
                        else:
                            self._update_gui("未能自动提取账号密钥，请在界面输入 AES 密钥后重试", gui)

            # 创建目标目录（如果不存在）
            os.makedirs(target_path, exist_ok=True)

            # 使用线程池处理文件
            max_workers = min(os.cpu_count() or 4, 8)  # 限制最大工作线程数
            self._update_gui(f"使用 {max_workers} 个线程进行解密处理...", gui)

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_file = {}

                # 提交所有任务（仅 .dat 文件）
                for file_path in all_files:
                    if self.should_stop:
                        break
                    if not file_path.lower().endswith(".dat"):
                        continue
                    future = executor.submit(self.parse_file, file_path, target_path, xor_key, gui,
                                             aes_key=self._pending_v2_aes)
                    future_to_file[future] = file_path

                # 等待完成
                for future in concurrent.futures.as_completed(future_to_file):
                    if self.should_stop:
                        executor.shutdown(wait=False)
                        self._update_gui("\n操作已取消。", gui)
                        return
                    # 结果已在parse_file中处理

            if not self.should_stop:
                self._update_gui("\n解密完成！", gui)

                # 询问是否打开目标目录
                if gui:
                    gui.root.after(500, lambda: gui.ask_open_directory(target_path))

        except Exception as e:
            self._update_gui(f"\n处理时发生错误: {str(e)}", gui)
        finally:
            self.running = False

    def _scan_directory(self, directory, file_list):
        """递归扫描目录并收集所有 .dat 文件（仅处理微信 dat 文件，避免扫描/读取海量无关文件导致卡死）"""
        try:
            for item in os.listdir(directory):
                full_path = os.path.join(directory, item)
                if os.path.isdir(full_path):
                    self._scan_directory(full_path, file_list)
                elif item.lower().endswith(".dat"):
                    file_list.append(full_path)
        except Exception as e:
            print(f"扫描目录时出错 {directory}: {str(e)}")

    def _update_gui(self, message, gui):
        """将消息添加到队列以更新GUI"""
        if gui:
            self.message_queue.put(message)
        else:
            print(message)

    def _process_messages(self, gui):
        """从队列处理消息并更新GUI"""
        try:
            # 每周期最多处理有限条日志，避免一次性处理海量消息导致GUI卡死、
            # 进度条来不及刷新而出现 0% 直接跳到 100% 的问题
            max_per_tick = 100
            count = 0
            while not self.message_queue.empty() and count < max_per_tick:
                message = self.message_queue.get_nowait()
                count += 1
                gui.log_area.insert(tk.END, f"\n{message}")
                gui.log_area.see(tk.END)  # 自动滚动到底部

            # 进度条与日志解耦：每个周期（约0.1秒）按当前已完成数实时刷新，
            # 让进度随时间平滑增长，而不是跳变到 100%
            if self.total_files > 0:
                progress = self.processed_files / self.total_files
                gui.progress_bar["value"] = progress * 100
                gui.progress_label.config(text=f"进度: {self.processed_files}/{self.total_files} ({progress:.1%})")

            # 更新按钮状态
            if self.running:
                gui.convert_btn.config(text="取消转换", command=lambda: self._cancel_conversion(gui))
            else:
                gui.convert_btn.config(text="开始转换", command=lambda: self._start_conversion(gui))

            # 如果仍在运行，或队列中还有日志未处理完，继续处理
            if self.running or not self.message_queue.empty():
                gui.root.after(100, lambda: self._process_messages(gui))
        except Exception as e:
            print(f"处理消息时出错: {str(e)}")
            if self.running or not self.message_queue.empty():
                gui.after(100, lambda: self._process_messages(gui))

    def _start_conversion(self, gui):
        """启动转换过程"""
        source_path = gui.source_entry.get()
        target_path = gui.target_entry.get()

        if not source_path or not target_path:
            self._update_gui("错误：请指定源路径和目标路径", gui)
            return

        gui.log_area.delete(1.0, tk.END)  # 清除日志区域
        gui.progress_bar["value"] = 0
        gui.progress_label.config(text="准备中...")

        self.convert(source_path, target_path, gui)

    def _cancel_conversion(self, gui):
        """取消正在进行的转换"""
        self.should_stop = True
        gui.convert_btn.config(text="取消中...", state=tk.DISABLED)
        self._update_gui("\n正在取消操作...", gui)

    def _inc_processed(self):
        """线程安全地递增已完成文件计数（多个工作线程会同时调用）"""
        with self._count_lock:
            self.processed_files += 1

    def parse_file(self, file_path, target_path, xor_key, gui=None, aes_key=None):
        """处理单个文件进行解密（支持微信3.x V3 与微信4.x V1/V2）"""
        try:
            # 跳过目录文件
            if os.path.isdir(file_path):
                new_target_path = os.path.join(target_path, os.path.basename(file_path))
                os.makedirs(new_target_path, exist_ok=True)
                return

            with open(file_path, 'rb') as reader:
                data = reader.read()
            file_name = os.path.basename(file_path).split('.')[0]
            file_size_kb = len(data) / 1000.0
            version = self._detect_version(data)
            ver_name = {0: "V3", 1: "V4-V1", 2: "V4-V2"}.get(version, "?")

            decrypted = None
            ext = None

            if version in (1, 2):
                # ============ 微信4.x：AES-ECB段 + 明文段 + XOR段 ============
                # 优先尾部推导（每文件），否则用传入的 xor_key 或账号缓存默认 XOR 密钥
                xk = (self._derive_xor_key_from_tail(data)
                      or xor_key or getattr(self, "_pending_v2_xor", None))
                if version == 1:
                    aes = V1_AES_KEY  # 硬编码常量，离线可解
                else:
                    aes = aes_key or getattr(self, "_pending_v2_aes", None)
                if not aes:
                    self._update_gui(
                        f"{os.path.basename(file_path)} (V2 文件需要账号 AES 密钥，请点击'从微信提取'或输入密钥后重试)",
                        gui)
                    self._inc_processed()
                    return
                try:
                    decrypted = self._decrypt_v4(data, xk, aes)
                except Exception as e:
                    self._update_gui(f"处理 {os.path.basename(file_path)} 时出错: {str(e)}", gui)
                    self._inc_processed()
                    return
                # 尾部推导的 XOR 密钥可能误判（页脚字节偶然满足 FFD9 校验模式，
                # 如 0xD9/0xFD 之类），若真实解码无效则回退尝试账号默认密钥
                alt_xk = xor_key or getattr(self, "_pending_v2_xor", None)
                if (not self._is_decodable_image(decrypted) and alt_xk and xk != alt_xk):
                    try:
                        decrypted = self._decrypt_v4(data, alt_xk, aes)
                    except Exception:
                        pass
                if not self._is_decodable_image(decrypted):
                    self._update_gui(
                        f"{os.path.basename(file_path)} (解密结果不是有效图片，密钥可能不正确或文件已损坏)",
                        gui)
                    self._inc_processed()
                    return
                ext = self._match_magic(decrypted)
            else:
                # ============ 微信3.x：整文件单字节 XOR（离线可解） ============
                xk = xor_key
                if not xk:
                    x_info = self.get_xor(file_path)
                    xk = x_info[1]
                if not xk:
                    self._update_gui(f"{os.path.basename(file_path)} (无法检测XOR值，已跳过)", gui)
                    self._inc_processed()
                    return
                decrypted = self._decrypt_v3(data, xk)
                if not self._is_valid_image(decrypted):
                    self._update_gui(
                        f"{os.path.basename(file_path)} (解密结果不是有效图片，可能文件已损坏)",
                        gui)
                    self._inc_processed()
                    return
                ext = self._match_magic(decrypted)

            if ext:
                output_file = os.path.join(target_path, f"{file_name}.{ext}")
            else:
                output_file = os.path.join(target_path, file_name)
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'wb') as writer:
                writer.write(decrypted)

            self._inc_processed()
            progress_msg = f"{os.path.basename(file_path)} ({ver_name}, 大小: {file_size_kb:.2f}kb)"
            self._update_gui(progress_msg, gui)

        except Exception as e:
            error_msg = f"处理 {os.path.basename(file_path)} 时出错: {str(e)}"
            self._update_gui(error_msg, gui)
            self._inc_processed()  # 即使出错也计数以保持进度准确

    @staticmethod
    def _match_magic(dec):
        """
        通过已解密的头部字节匹配常见图片格式魔数

        Args:
            dec: 已使用候选密钥解密的头部字节

        Returns:
            str: 匹配到的文件扩展名，未匹配则返回 None
        """
        if dec.startswith(b"\xff\xd8\xff"):              # JPEG（SOI + APP 标记）
            return "jpg"
        if dec.startswith(b"\x89PNG\r\n\x1a\n"):          # PNG 标准签名
            return "png"
        if dec.startswith(b"GIF8"):                       # GIF87a / GIF89a
            return "gif"
        if dec.startswith(b"BM"):                         # BMP
            return "bmp"
        if dec.startswith(b"RIFF") and len(dec) >= 12 and dec[8:12] == b"WEBP":
            return "webp"                                 # WebP（RIFF....WEBP）
        if dec.startswith(b"II*\x00"):                    # TIFF（小端）
            return "tif"
        if dec.startswith(b"MM\x00*"):                    # TIFF（大端）
            return "tif"
        if dec.startswith(b"\x00\x00\x01\x00"):           # ICO
            return "ico"
        # HEIC（ISO BMFF 容器，品牌 heic/heix/hevc/mif1/msf1）
        if len(dec) >= 12 and dec[4:8] == b"ftyp" and dec[8:12] in (b"heic", b"heix", b"hevc", b"mif1", b"msf1"):
            return "heic"
        return None

    def get_xor(self, file_path):
        """
        从文件头检测XOR密钥和文件类型

        返回:
            tuple: (file_extension, xor_key)
        """
        if not file_path or not os.path.exists(file_path):
            return [None, None]

        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)  # 读取前16个字节以支持更长的签名

            return self.get_xor_from_bytes(header)
        except Exception as e:
            print(f"读取文件头时出错: {str(e)}")
            return [None, None]

    def get_xor_from_bytes(self, header_bytes):
        """
        从头部字节确定文件类型和XOR密钥（增强版，支持微信聊天图片 .dat 解密）

        微信聊天图片的 .dat 文件是对整个文件按字节与单个密钥进行 XOR 加密，
        因此：
          1) 先遍历 0-255 全部密钥，将头部解密后与常见图片魔数比对（通用且不易误判）；
          2) 若未命中图片魔数，再用通用文件签名表逐字节完整校验（视频、音频、文档等）。

        Args:
            header_bytes: 文件的前几个字节

        Returns:
            tuple: (file_extension, xor_key)
        """
        if not header_bytes:
            return [None, None]

        # 将字节转换为整数列表
        bytes_values = [b & 0xFF for b in header_bytes]
        if len(bytes_values) < 3:
            return [None, None]

        # 1) 暴力枚举密钥并校验图片魔数
        #    微信聊天图片的 .dat 只使用 0-255 范围内的单个字节作为密钥，
        #    用头部前16字节逐密钥试算即可覆盖所有情况，从根本上避免“无法检测XOR值”。
        for key in range(256):
            decrypted = bytes([b ^ key for b in bytes_values[:16]])
            ext = self._match_magic(decrypted)
            if ext:
                return [ext, key]

        # 2) 通用文件签名表匹配（非图片类型：视频、音频、文档等）
        for signature_hex, extension in self.FILE_TYPE_MAP.items():
            # 检查是否有足够的字节进行比较
            if len(signature_hex) < 6:
                continue

            # 将十六进制签名转换为字节列表
            hex_values = []
            signature_len = min(len(signature_hex), len(bytes_values) * 2)

            for i in range(0, signature_len, 2):
                if i + 1 < len(signature_hex):
                    hex_values.append(int(signature_hex[i:i + 2], 16))

            # 检查是否有足够的头字节进行比较
            bytes_len = min(len(bytes_values), len(hex_values))
            if bytes_len < 3:
                continue

            # 以第一个字节推导密钥，并逐字节完整校验，避免误判
            key = bytes_values[0] ^ hex_values[0]
            if all((bytes_values[i] ^ key) == hex_values[i] for i in range(bytes_len)):
                return [extension, key]

        return [None, None]

    # ==================== 微信 4.x (V1/V2) 解密支持 ====================

    @staticmethod
    def _detect_version(data):
        """
        检测微信 dat 文件版本

        返回:
            0 = V3（微信3.x，整文件单字节 XOR，离线可解）
            1 = V4-V1（微信4.x，AES密钥硬编码，离线可解）
            2 = V4-V2（微信4.x，AES密钥为账号密钥，需提取/缓存）
        """
        sig = data[:6]
        if sig == SIG_V1:
            return 1
        if sig == SIG_V2:
            return 2
        return 0

    @staticmethod
    def _derive_xor_key_from_tail(data):
        """
        从文件末尾推导 V4 的 XOR 密钥
        JPEG 以 FF D9（EOI）结尾，故：xor_key = 倒数第2字节 ^ 0xFF，校验末字节 ^ 0xD9
        """
        if not data or len(data) < 2:
            return None
        x, y = data[-2], data[-1]
        k = x ^ 0xFF
        if (y ^ 0xD9) == k:
            return k
        return None

    @staticmethod
    def _is_valid_image(data):
        """校验解密结果是否为有效图片（JPEG/PNG/GIF/BMP/WebP）"""
        if not data or len(data) < 4:
            return False
        if data[:3] == b"\xff\xd8\xff" and data[-2:] == b"\xff\xd9":
            return True
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            return True
        if data[:6] in (b"GIF87a", b"GIF89a"):
            return True
        if data[:2] == b"BM":
            return True
        if data[:4] == b"RIFF" and len(data) >= 12 and data[8:12] == b"WEBP":
            return True
        return False

    def _is_decodable_image(self, data):
        """更强校验：魔数通过后，用 PIL 完整解码确认无数据流损坏。

        仅靠魔数+尾部会误判——错误密钥经页脚截断后也可能恰好以 FFD9 结尾
        （如尾部误判出的 0xD9/0xFD），此时必须真实解码才能区分。
        """
        if not self._is_valid_image(data):
            return False
        try:
            from PIL import Image
            import io as _io
            im = Image.open(_io.BytesIO(data))
            im.load()
            return True
        except ImportError:
            # PIL 不可用时退回魔数校验
            return True
        except Exception:
            # 解码失败（数据流损坏/截断）→ 视为无效
            return False

    def _decrypt_v4(self, data, xor_key, aes_key):
        """微信4.x (V1/V2) 混合解密：AES-ECB段 + (固定16字节标记,跳过) + 单字节XOR段"""
        if not _HAS_CRYPTO:
            raise RuntimeError("缺少 pycryptodome，请先安装: pip install pycryptodome")
        if len(data) < 15:
            raise ValueError("文件过小，不是有效的微信4.x dat")
        header, rest = data[:15], data[15:]
        signature, aes_size, xor_size = struct.unpack("<6sLLx", header)
        if signature == SIG_V1:
            aes_key = V1_AES_KEY
        # AES 段长度对齐到 16 字节块
        if aes_size % AES_BLOCK:
            aes_size += AES_BLOCK - aes_size % AES_BLOCK
        aes_data = rest[:aes_size]
        if xor_size > 0:
            raw_data = rest[aes_size:-xor_size]
            xor_data = rest[len(rest) - xor_size:]
        else:
            raw_data = rest[aes_size:]
            xor_data = b""
        # 跳过 AES 段与 XOR 段之间的固定 16 字节标记前缀（非图片数据）。
        # 若把它当明文拼进图片，会造成数据错位、解码损坏/偏色。
        # 兼容两类文件：
        #   _t 缩略图：raw 段恰好就是标记本身（16字节）→ 整体剥掉
        #   _h 原图：raw 段 = 标记(16) + 原始图片数据 → 只剥掉标记前缀，保留图片数据
        if raw_data[:len(V4_RAW_MARKER)] == V4_RAW_MARKER:
            raw_data = raw_data[len(V4_RAW_MARKER):]
        key_bytes = aes_key.encode("ascii")[:16] if isinstance(aes_key, str) else bytes(aes_key)[:16]
        decrypted_aes = AES.new(key_bytes, AES.MODE_ECB).decrypt(aes_data)
        try:
            decrypted_aes = AesPadding.unpad(decrypted_aes, AES_BLOCK)
        except Exception:
            pass
        xored_data = bytes(b ^ (xor_key & 0xFF) for b in xor_data)
        result = decrypted_aes + raw_data + xored_data
        # 微信会在 JPEG 图片末尾追加元数据页脚（约24字节，如 a99cc42c...）。
        # 剥离页脚得到干净图片，否则严格校验（须以 FFD9 结尾）会误判"密钥不正确"。
        # 仅对 JPEG 处理；PNG 以 IEND 结尾不受影响。
        if result[:3] == b"\xff\xd8\xff":
            idx = result.rfind(b"\xff\xd9")
            if idx > 0:
                result = result[:idx + 2]
        return result

    def _decrypt_v3(self, data, xor_key):
        """微信3.x 单字节 XOR（整文件）"""
        return bytes(b ^ (xor_key & 0xFF) for b in data)

    # ---------------- 账号 AES 密钥（V2）获取与缓存 ----------------

    def _extract_account_from_path(self, path):
        """从路径中猜测微信账号目录名（形如 xwechat_files\\<account>）"""
        norm = os.path.normpath(path or "")
        parts = norm.replace("/", os.sep).split(os.sep)
        for i, part in enumerate(parts):
            if part.lower() == "xwechat_files" and i + 1 < len(parts):
                return parts[i + 1]
        return ""

    def _key_file_path(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "wechat_image_keys.json")

    def _load_cached_keys(self):
        try:
            with open(self._key_file_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_cached_keys(self, account, aes_key, xor_key):
        try:
            keys = self._load_cached_keys()
            keys[account or "_default"] = {"aes": aes_key, "xor": int(xor_key or 0)}
            with open(self._key_file_path(), "w", encoding="utf-8") as f:
                json.dump(keys, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print("保存密钥失败:", e)

    def _get_cached_key(self, account):
        keys = self._load_cached_keys()
        for key_name in (account, "_default"):
            item = keys.get(key_name)
            if isinstance(item, dict) and item.get("aes"):
                try:
                    return item["aes"], int(item.get("xor") or 0)
                except Exception:
                    return item["aes"], None
        return None, None

    def _find_valid_cached_key(self, source_path):
        """
        遍历缓存密钥，用 V2 模板文件校验出正确的那把（用于无法从路径判断账号的情况）
        返回 (account, aes, xor) 或 (None, None, None)
        """
        template = None
        if os.path.isfile(source_path):
            try:
                d = open(source_path, "rb").read()
                if self._detect_version(d) == 2:
                    template = d
            except Exception:
                pass
        else:
            for root, _, files in os.walk(source_path):
                for f in files:
                    if f.lower().endswith(".dat"):
                        try:
                            d = open(os.path.join(root, f), "rb").read()
                        except Exception:
                            continue
                        if self._detect_version(d) == 2:
                            template = d
                            break
                if template:
                    break
        if not template:
            return None, None, None
        xk = self._derive_xor_key_from_tail(template) or 0
        keys = self._load_cached_keys()
        for account, item in keys.items():
            if not isinstance(item, dict) or not item.get("aes"):
                continue
            aes = item["aes"]
            try:
                img = self._decrypt_v4(template, xk, aes)
                if self._is_valid_image(img):
                    return account, aes, item.get("xor") or xk
            except Exception:
                continue
        return None, None, None

    def _scan_wechat_memory(self, template_data, xor_key, gui=None):
        """
        扫描 Weixin.exe 进程内存寻找 V2 图片 AES 密钥（Windows）
        密钥为内存中 16~64 位 ASCII 字母数字串（或 UTF-16LE）的前 16 字符，
        用已知密文块 + 完整文件解密双重验证。
        """
        def log(msg):
            if gui is not None:
                try:
                    gui.log_area.insert(tk.END, f"\n{msg}")
                    gui.log_area.see(tk.END)
                except Exception:
                    print(msg)
            else:
                print(msg)

        ct_block = template_data[15:31]

        def cheap_check(key):
            try:
                kb = key.encode("ascii") if isinstance(key, str) else bytes(key)
                if len(kb) != 16:
                    return False
                pt = AES.new(kb, AES.MODE_ECB).decrypt(ct_block)
                if pt[:3] == b"\xff\xd8\xff":
                    return True
                if pt[:8] == b"\x89PNG\r\n\x1a\n":
                    return True
                if pt[:4] in (b"GIF8", b"GIF9"):
                    return True
                return False
            except Exception:
                return False

        def full_check(key):
            try:
                img = self._decrypt_v4(template_data, xor_key, key)
                return self._is_valid_image(img)
            except Exception:
                return False

        if os.name != "nt":
            return None

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                               ctypes.c_void_p, ctypes.c_size_t,
                                               ctypes.POINTER(ctypes.c_size_t)]
        kernel32.ReadProcessMemory.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = wintypes.BOOL

        class MBI(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        kernel32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                            ctypes.POINTER(MBI), ctypes.c_size_t]
        kernel32.VirtualQueryEx.restype = ctypes.c_size_t

        ASCII_RUN = re.compile(rb"[A-Za-z0-9]+")
        UTF16_RUN = re.compile(rb"(?:[A-Za-z0-9]\x00)+")
        MAX_REGION = 200 * 1024 * 1024
        CHUNK = 4 * 1024 * 1024
        OVERLAP = 68
        PROT_IN = (0x02, 0x04, 0x08, 0x40, 0x80)

        try:
            out = subprocess.run(["tasklist"], capture_output=True, text=True).stdout
        except Exception:
            out = ""
        pids = []
        for line in out.splitlines():
            low = line.lower()
            if "weixin.exe" in low or "wechatappex.exe" in low:
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        pids.append(int(part))
                        break
        if not pids:
            log("未找到运行中的微信进程 (Weixin.exe)")
            return None

        seen = set()
        for pid in pids:
            handle = kernel32.OpenProcess(0x0410, False, pid)
            if not handle:
                continue
            log(f"扫描微信进程 PID {pid} 内存...")
            try:
                address = 0
                regions = 0
                while address < 0x7FFF_FFFF_FFFF:
                    info = MBI()
                    r = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address),
                                                ctypes.byref(info), ctypes.sizeof(info))
                    if not r:
                        break
                    base = int(info.BaseAddress or 0)
                    size = int(info.RegionSize)
                    if size <= 0:
                        break
                    next_addr = base + size
                    if next_addr <= address:
                        break
                    state = int(info.State)
                    prot = int(info.Protect)
                    if (state == 0x1000 and 0 < size <= MAX_REGION
                            and not (prot & 0x100) and not (prot & 0x01)
                            and (prot & 0xFF) in PROT_IN):
                        regions += 1
                        offset = 0
                        trailing = b""
                        while offset < size:
                            want = min(CHUNK, size - offset)
                            buf = ctypes.create_string_buffer(want)
                            read = ctypes.c_size_t(0)
                            ok = kernel32.ReadProcessMemory(
                                handle, ctypes.c_void_p(base + offset),
                                buf, want, ctypes.byref(read))
                            if not ok or read.value <= 0:
                                offset += want
                                continue
                            chunk = buf.raw[:read.value]
                            data = trailing + chunk
                            for m in ASCII_RUN.finditer(data):
                                ln = m.end() - m.start()
                                if 16 <= ln <= 64:
                                    key = m.group()[:16].decode("ascii")
                                    if key not in seen and cheap_check(key) and full_check(key):
                                        log(f"  已找到 AES 密钥: {key}")
                                        return key
                                    seen.add(key)
                            for m in UTF16_RUN.finditer(data):
                                ln = m.end() - m.start()
                                if 32 <= ln <= 128:
                                    key = m.group()[::2][:16].decode("ascii")
                                    if key not in seen and cheap_check(key) and full_check(key):
                                        log(f"  已找到 AES 密钥(UTF16): {key}")
                                        return key
                                    seen.add(key)
                            trailing = data[-OVERLAP:] if len(chunk) == want else b""
                            offset += want
                    address = next_addr
                log(f"  PID {pid}: 扫描 {regions} 个区域，未命中")
            finally:
                kernel32.CloseHandle(handle)
        return None

    def extract_key_from_wechat(self, source_path, gui=None):
        """
        从运行中的微信进程提取 V2 账号 AES 密钥（Windows，需管理员权限+微信运行中）

        返回:
            (aes_key, xor_key) 或 None
        """
        template = None
        if os.path.isfile(source_path):
            try:
                d = open(source_path, "rb").read()
                if self._detect_version(d) == 2:
                    template = d
            except Exception:
                pass
        else:
            for root, _, files in os.walk(source_path):
                for f in files:
                    if f.lower().endswith(".dat"):
                        try:
                            d = open(os.path.join(root, f), "rb").read()
                        except Exception:
                            continue
                        if self._detect_version(d) == 2:
                            template = d
                            break
                if template:
                    break
        if not template:
            msg = "未找到微信4.x V2 模板文件，无法提取账号密钥"
            if gui:
                try:
                    gui.log_area.insert(tk.END, f"\n{msg}")
                    gui.log_area.see(tk.END)
                except Exception:
                    print(msg)
            else:
                print(msg)
            return None

        xor_key = self._derive_xor_key_from_tail(template)
        if xor_key is None:
            xor_key = 0
        aes = self._scan_wechat_memory(template, xor_key, gui)
        if aes:
            return aes, xor_key
        return None

    # ---------------- 源路径 / 版本自动检测 ----------------

    @staticmethod
    def _detect_wechat_source():
        """
        自动检测微信数据目录（账号目录）

        依次检查常见位置，优先返回包含 msg\\attach 的账号目录
        """
        home = os.path.expanduser("~")
        roots = [
            r"D:\Documents\xwechat_files",
            os.path.join(home, "Documents", "xwechat_files"),
            os.path.join(home, "Documents", "WeChat Files"),
        ]
        candidates = []
        for root in roots:
            if not os.path.isdir(root):
                continue
            try:
                names = sorted(os.listdir(root))
            except Exception:
                continue
            for name in names:
                p = os.path.join(root, name)
                if os.path.isdir(p) and not name.startswith("."):
                    candidates.append(p)
        # 优先返回包含 msg/attach 的账号目录
        for c in candidates:
            if os.path.isdir(os.path.join(c, "msg", "attach")):
                return c
        if candidates:
            return candidates[0]
        return ""

    @staticmethod
    def _detect_source_version(source_path):
        """
        扫描源路径判断微信图片 dat 版本集合

        返回:
            set: 包含 0(V3) / 1(V4-V1) / 2(V4-V2) 的集合，未检测到则为空集
        """
        if not source_path or not os.path.exists(source_path):
            return set()
        paths = []
        if os.path.isfile(source_path):
            paths = [source_path]
        else:
            for root, _, files in os.walk(source_path):
                for f in files:
                    if f.lower().endswith(".dat"):
                        paths.append(os.path.join(root, f))
                        if len(paths) >= 40:  # 采样前40个即可
                            break
                if len(paths) >= 40:
                    break
        versions = set()
        for p in paths:
            try:
                with open(p, "rb") as f:
                    head = f.read(6)
                if head == SIG_V1:
                    versions.add(1)
                elif head == SIG_V2:
                    versions.add(2)
                else:
                    versions.add(0)
            except Exception:
                continue
        return versions

    @staticmethod
    def _describe_versions(versions):
        """将版本集合转为可读描述"""
        if not versions:
            return "未检测到微信 dat 文件"
        if versions == {0}:
            return "微信3.x V3（整文件XOR，离线可解）"
        if versions == {1}:
            return "微信4.x V1（AES硬编码，离线可解）"
        if versions == {2}:
            return "微信4.x V2（需账号AES密钥）"
        labels = {0: "V3", 1: "V1", 2: "V2"}
        return "混合版本: " + " / ".join(labels.get(v, str(v)) for v in sorted(versions))


class WxChatDecryptGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("微信图片解密工具")
        self.root.geometry("780x560")
        self.converter = WxChatImgRevert()

        # 设置主题样式
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", background="#ccc")

        self.create_widgets()
        # 启动后自动检测源路径与微信版本
        self.root.after(200, self.auto_detect)

    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 路径框架
        path_frame = ttk.LabelFrame(main_frame, text="路径设置", padding="5")
        path_frame.pack(fill=tk.X, pady=5)

        # 源路径
        ttk.Label(path_frame, text="源路径:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.source_entry = ttk.Entry(path_frame, width=50)
        self.source_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.source_entry.bind("<KeyRelease>", lambda e: self.refresh_version())
        self.source_entry.bind("<FocusOut>", lambda e: self.refresh_version())
        src_btns = ttk.Frame(path_frame)
        src_btns.grid(row=0, column=2, padx=5)
        ttk.Button(src_btns, text="浏览", command=lambda: self.browse_folder(self.source_entry)).pack(side=tk.LEFT, padx=2)
        ttk.Button(src_btns, text="自动检测", command=self.auto_detect).pack(side=tk.LEFT, padx=2)

        # 版本信息（自动判断）
        ttk.Label(path_frame, text="版本:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.version_label = ttk.Label(path_frame, text="检测中...", foreground="#2b7ae8")
        self.version_label.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        # 目标路径
        ttk.Label(path_frame, text="目标路径:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.target_entry = ttk.Entry(path_frame, width=50)
        self.target_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(path_frame, text="浏览", command=lambda: self.browse_folder(self.target_entry)).grid(row=2, column=2,
                                                                                                        padx=5)

        # 账号密钥框架（微信4.x V2 文件需要，V1/V3 无需）
        key_frame = ttk.LabelFrame(main_frame, text="微信4.x 账号密钥（V2文件需要，V1/V3无需）", padding="5")
        key_frame.pack(fill=tk.X, pady=5)

        ttk.Label(key_frame, text="AES密钥:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.aes_entry = ttk.Entry(key_frame, width=40)
        self.aes_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(key_frame, text="从微信提取", command=self._extract_key_gui).grid(row=0, column=2, padx=5)
        self.key_status = ttk.Label(key_frame, text="留空则解密时自动尝试从微信进程提取")
        self.key_status.grid(row=0, column=3, sticky=tk.W, padx=5)

        # 日志框架
        log_frame = ttk.LabelFrame(main_frame, text="处理日志", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 日志区域
        self.log_area = scrolledtext.ScrolledText(log_frame, width=80, height=15)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_area.insert(tk.END, "欢迎使用微信图片解密工具。请选择源路径和目标路径，然后点击'开始解密'按钮。")

        # 进度框架
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=5)

        # 进度条
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # 进度标签
        self.progress_label = ttk.Label(progress_frame, text="就绪")
        self.progress_label.pack(side=tk.RIGHT, padx=5)

        # 转换按钮（主要操作，突出显示，居中）
        self.convert_btn = tk.Button(main_frame, text="开始转换",
                                     command=self._start_conversion,
                                     bg="#2b7ae8", fg="white",
                                     activebackground="#1f66c9", activeforeground="white",
                                     font=("Microsoft YaHei", 10, "bold"),
                                     height=1, padx=24, pady=8, relief="flat", cursor="hand2")
        self.convert_btn.pack(pady=10)

    def browse_folder(self, entry_widget):
        """打开文件对话框选择文件夹"""
        folder_path = filedialog.askdirectory()
        if folder_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, folder_path)
            self.refresh_version()

    def auto_detect(self):
        """自动检测源路径、目标路径与微信图片版本"""
        src = self.converter._detect_wechat_source()
        if src:
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, src)
            self.log_area.insert(tk.END, f"\n已自动检测源路径: {src}")
        else:
            self.log_area.insert(tk.END, "\n未自动检测到微信数据目录，请点击'浏览'手动选择源路径")
        self.refresh_version()
        self.log_area.see(tk.END)

    def refresh_version(self):
        """根据源路径刷新微信版本显示、目标路径与缓存密钥"""
        src = self.source_entry.get().strip()
        versions = self.converter._detect_source_version(src)
        self.version_label.config(text=self.converter._describe_versions(versions))
        # 自动补全目标路径
        if not self.target_entry.get().strip() and src and os.path.isdir(src):
            parent = os.path.dirname(src)
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, os.path.join(parent, os.path.basename(src) + "_decoded"))
        # V2 且未输入密钥时，自动载入账号缓存密钥
        if versions == {2} and not self.aes_entry.get().strip():
            account = self.converter._extract_account_from_path(src)
            aes, _ = self.converter._get_cached_key(account)
            if aes:
                self.aes_entry.delete(0, tk.END)
                self.aes_entry.insert(0, aes)
                self.key_status.config(text="已自动载入缓存密钥")

    def _extract_key_gui(self):
        """从运行中的微信进程提取账号 AES 密钥"""
        src = self.source_entry.get()
        if not src:
            messagebox.showwarning("提示", "请先选择源路径（包含 V2 .dat 文件的目录）")
            return
        self.key_status.config(text="提取中...")
        self.log_area.insert(tk.END, "\n正在从微信进程提取账号AES密钥...")
        self.log_area.see(tk.END)
        result = self.converter.extract_key_from_wechat(src, self)
        if result:
            aes, xk = result
            self.aes_entry.delete(0, tk.END)
            self.aes_entry.insert(0, aes)
            self.key_status.config(text=f"已提取 (xor={xk})")
            account = self.converter._extract_account_from_path(src)
            self.converter._save_cached_keys(account, aes, xk)
            self.log_area.insert(tk.END, f"\n已提取账号AES密钥: {aes}，并已缓存供离线复用")
            self.log_area.see(tk.END)
        else:
            self.key_status.config(text="提取失败")
            self.log_area.insert(tk.END, "\n未能从微信进程提取密钥：请确认微信已运行、当前以管理员身份运行，或在 AES密钥 框中手动输入")
            self.log_area.see(tk.END)

    def _start_conversion(self):
        """启动转换过程"""
        self.converter._start_conversion(self)

    def ask_open_directory(self, directory):
        """询问是否打开目标目录"""
        if messagebox.askyesno("解密完成", "所有文件已解密完成，是否打开目标目录查看文件？"):
            self.open_directory(directory)

    def open_directory(self, directory):
        """打开指定目录"""
        try:
            if os.name == 'nt':  # Windows
                os.startfile(directory)
            elif os.name == 'posix':  # macOS, Linux
                if os.path.exists('/usr/bin/open'):  # macOS
                    subprocess.call(['open', directory])
                else:  # Linux
                    subprocess.call(['xdg-open', directory])
            else:
                self.log_area.insert(tk.END, "\n无法自动打开目录，请手动打开: " + directory)
        except Exception as e:
            self.log_area.insert(tk.END, f"\n打开目录时发生错误: {str(e)}")
            messagebox.showerror("错误", f"无法打开目录: {str(e)}")


def main():
    """命令行接口"""
    import argparse

    parser = argparse.ArgumentParser(description='微信图片解密工具')
    parser.add_argument('--source', '-s', help='包含加密文件的源路径')
    parser.add_argument('--target', '-t', help='解密文件的目标目录')
    parser.add_argument('--gui', '-g', action='store_true', help='启动GUI模式')

    args = parser.parse_args()

    if args.gui or (not args.source and not args.target):
        root = tk.Tk()
        app = WxChatDecryptGUI(root)
        root.protocol("WM_DELETE_WINDOW", root.destroy)  # 确保窗口关闭时终止程序
        root.mainloop()
    elif args.source and args.target:
        converter = WxChatImgRevert()
        thread = converter.convert(args.source, args.target)
        thread.join()  # 等待后台转换线程完成
        print(f"\n处理完成，共处理 {converter.processed_files} 个文件。")
    else:
        print("请同时指定源路径和目标路径，或使用--gui参数启动图形界面。")
        parser.print_help()


if __name__ == "__main__":
    main()