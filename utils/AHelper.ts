import {_AHelperCore} from "./_inner/_AHelper.core";
import {_AHelperHook} from "./_inner/_AHelper.hook";
import {_AHelperWatch} from "./_inner/_AHelper.watch";
import {_AHelperCast} from "./_inner/_AHelper.cast";
import {_AHelperString} from "./_inner/_AHelper.string";
import {_AHelperCrypto} from "./_inner/_AHelper.crypto";
import {_AHelperSearch} from "./_inner/_AHelper.search";

/**
 * Android java帮助类工具模块
 */
export const AHelper = (() => {
    return {
        ..._AHelperCore,
        ..._AHelperCast,
        ..._AHelperHook,
        ..._AHelperWatch,
        ..._AHelperCrypto,
        ..._AHelperSearch,
        ..._AHelperString,
    };
})();