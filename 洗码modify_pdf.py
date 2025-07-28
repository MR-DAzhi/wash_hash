import os
import random
import sys

def modify_file(file_path):
    try:
        with open(file_path, "ab") as f:
            junk = b"\n#RandomData-" + os.urandom(random.randint(8, 32))
            f.write(junk)
        print(f"文件已修改：{file_path}")
    except Exception as e:
        print(f"修改失败：{e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: file_hash_randomizer.exe 文件路径")
    else:
        modify_file(sys.argv[1]) 