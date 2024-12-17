import {Flog} from "./utils/Flog";
import {AHelper} from "./utils/AHelper";

function main() {
    Java.perform(() => {
        console.log("hello Frida.")
    })
}

setImmediate(main)
