import {android} from "./utils/android";
import FindClazz = android.FindClazz;
import FindClassloader = android.FindClassloader;
import HookClazz = android.HookClazz;

function main() {
    Java.perform(() => {
        console.log(FindClazz.TAG)
        console.log(FindClassloader.TAG)
        console.log(HookClazz.TAG)
    })
}

setImmediate(main)
