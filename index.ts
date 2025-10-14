import {Flog} from "./utils/Flog";
import {AHelper} from "./utils/AHelper";

function main() {
    Java.perform(() => {
        Flog.i("hello Frida.")
    })
}

setImmediate(main)
