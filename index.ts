import {android} from "./utils/android";
import FindClazz = android.FindClazz;
import FindClassloader = android.FindClassloader;
import HookClazz = android.HookClazz;
import WatchCipher = android.WatchCrypto;

function main() {
    Java.perform(() => {
        WatchCipher.watch_crypto(false);
    })
}

setImmediate(main)
