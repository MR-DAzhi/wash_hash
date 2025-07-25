import os
import hashlib
import zlib
import struct
import shutil

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
                # 采样：读头尾各1MB
                head = f.read(sample_size)
                f.seek(-sample_size, os.SEEK_END)
                tail = f.read(sample_size)
                sample_data = head + tail

                md5.update(sample_data)
                sha1.update(sample_data)
                crc32 = zlib.crc32(sample_data)
                crc64.update(sample_data)
            else:
                # 全文件读取
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


def modify_and_save_new_file(orig_path):
    file_size = os.path.getsize(orig_path)
    if file_size < 5:
        print(f"跳过小文件：{orig_path}")
        return

    print(f"处理：{orig_path}")
    print("修改前哈希：")
    hashes_before = compute_hashes(orig_path)
    for k, v in hashes_before.items():
        print(f"{k}: {v}")

    base, ext = os.path.splitext(orig_path)
    new_path = f"{base}_washed{ext}"

    try:
        shutil.copyfile(orig_path, new_path)
    except Exception as e:
        print(f"复制文件失败：{e}")
        return

    try:
        with open(new_path, 'r+b') as f:
            f.seek(-5, os.SEEK_END)
            tail = bytearray(f.read(5))
            for i in range(5):
                tail[i] ^= 0xAA  # 异或操作
            f.seek(-5, os.SEEK_END)
            f.write(tail)
        print("已修改新文件末尾5字节。")
    except Exception as e:
        print(f"修改失败：{e}")
        return

    print("修改后哈希：")
    hashes_after = compute_hashes(new_path)
    for k, v in hashes_after.items():
        print(f"{k}: {v}")
    print("-" * 40)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法：python script.py 文件1 [文件2 ...]")
    else:
        for file_path in sys.argv[1:]:
            if os.path.isfile(file_path):
                modify_and_save_new_file(file_path)
            else:
                print(f"找不到文件：{file_path}")
