import {_FindClazz} from "./android/find_clazz";
import {_FindClassloader} from "./android/find_classloader";
import {_Helper} from "./android/helper";
import {_HookClazz} from "./android/hook_clazz";
import {_Anti} from "./android/anti";
import {_WatchViews} from "./android/watch_views";

export namespace android {
    export class Helper extends _Helper {
    }

    export class FindClazz extends _FindClazz {
    }

    export class FindClassloader extends _FindClassloader {
    }

    export class HookClazz extends _HookClazz {

    }

    export class Anit extends _Anti {

    }

    export class WatchViews extends _WatchViews {
    }
}

/*
// 也可以使用导出对象的方式（不推荐）
export const android = {
    FindClassLoader: _FindClassLoader,
    FindClazz: _FindClazz
}
*/