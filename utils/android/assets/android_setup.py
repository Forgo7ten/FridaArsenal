import os

if __name__ == '__main__':
    os.system('adb push ./fgson.dex /data/local/tmp/fgson.dex')
    os.system('adb shell su -c "chmod 777 /data/local/tmp/fgson.dex"')
    print("install fgson success.")
    pass
