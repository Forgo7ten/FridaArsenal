import {Flog} from "./utils/Flog";
import {AHelper} from "./utils/AHelper";
import {NHelper} from "./utils/NHelper";

function main() {
    Java.perform(() => {
        Flog.i("hello Frida.")
        NHelper.watch_so_load()
        AHelper.watch_logcat()
    })
}

setImmediate(main)
