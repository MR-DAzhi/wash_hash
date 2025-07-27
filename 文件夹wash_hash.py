import os
import hashlib
import zlib
import struct

# CRC64 使用 ECMA-182 多项式
class CRC64:
    def __init__(self):
        self.table = self._generate_table()
        self.crc = 0xFFFFFFFFFFFFFFFF

    def _generate_table(self):
        poly = 0xC96C5795D7870F42
        table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ poly
                else:
                    crc >>= 1
            table.append(crc)
        return table

    def update(self, data):
        for b in data:
            self.crc = self.table[(self.crc ^ b) & 0xFF] ^ (self.crc >> 8)

    def digest(self):
        return struct.pack('<Q', self.crc ^ 0xFFFFFFFFFFFFFFFF)

    def hexdigest(self):
        return format(self.crc ^ 0xFFFFFFFFFFFFFFFF, '016x')


def compute_hashes(file_path, use_sample=True):
    file_size = os.path.getsize(file_path)
    sample_size = 1024 * 1024  # 1MB
    threshold = 100 * 1024 * 1024  # 超过 100MB 使用采样

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    crc32 = 0
    crc64 = CRC64()

    try:
        with open(file_path, 'rb') as f:
            if use_sample and file_size > threshold:
                head = f.read(sample_size)
                f.seek(-sample_size, os.SEEK_END)
                tail = f.read(sample_size)
                sample_data = head + tail

                md5.update(sample_data)
                sha1.update(sample_data)
                crc32 = zlib.crc32(sample_data)
                crc64.update(sample_data)
            else:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    crc32 = zlib.crc32(chunk, crc32)
                    crc64.update(chunk)

        return {
            'MD5': md5.hexdigest(),
            'SHA1': sha1.hexdigest(),
            'CRC32': format(crc32 & 0xFFFFFFFF, '08x'),
            'CRC64': crc64.hexdigest(),
        }
    except Exception as e:
        return {'error': str(e)}


def modify_file_in_place(path):
    try:
        file_size = os.path.getsize(path)
        if file_size < 5:
            print(f"跳过小文件：{path}")
            return

        print(f"\n处理文件：{path}")
        print("修改前哈希：")
        hashes_before = compute_hashes(path)
        for k, v in hashes_before.items():
            print(f"{k}: {v}")

        with open(path, 'r+b') as f:
            f.seek(-5, os.SEEK_END)
            tail = bytearray(f.read(5))
            for i in range(5):
                tail[i] ^= 0xAA
            f.seek(-5, os.SEEK_END)
            f.write(tail)

        print("已原地修改末尾5字节。")
        print("修改后哈希：")
        hashes_after = compute_hashes(path)
        for k, v in hashes_after.items():
            print(f"{k}: {v}")
        print("-" * 40)

    except Exception as e:
        print(f"处理失败：{path} 错误：{e}")


def process_input(path):
    if os.path.isfile(path):
        modify_file_in_place(path)
    elif os.path.isdir(path):
        print(f"\n遍历文件夹：{path}")
        for root, dirs, files in os.walk(path):
            for name in files:
                full_path = os.path.join(root, name)
                modify_file_in_place(full_path)
    else:
        print(f"无效路径：{path}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法：拖动文件或文件夹到本程序上即可")
    else:
        for input_path in sys.argv[1:]:
            process_input(input_path)
