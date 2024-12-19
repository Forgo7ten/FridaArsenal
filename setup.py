import os

if __name__ == '__main__':
    # npm install
    os.system('npm install')
    # pip install
    os.system('pip install -r requirements.txt')
    # install fgson.dex
    os.system('adb push ./fgson.dex /data/local/tmp/fgson.dex')
    os.system('adb shell su -c "chmod 777 /data/local/tmp/fgson.dex"')
    pass
