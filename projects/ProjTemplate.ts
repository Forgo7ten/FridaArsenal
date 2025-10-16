import {AHelper} from "../utils/AHelper";
import {NHelper} from "../utils/NHelper";
import {Flog} from "../utils/Flog";

/**
 * use in index.ts
 * import {ProjTemplate} from "./projects/ProjTemplate";
 * setImmediate(ProjTemplate.main)
 */
export const ProjTemplate = (() => {
    function main() {
        Flog.setOptions({level: Flog.LOG_LEVEL_INFO})
        Flog.i("hello.");
    }

    return {
        main,
    }
})()