import {Flog} from "./Flog";
import Wrapper = Java.Wrapper;

export namespace AHelper {
    const _HOOK_TAG = "JAVA_HOOK"
    const _HELPER_TAG = "Helper"

    /**
     * Java.cast java对象
     * @param jobj java对象
     * @param cls 认为的该对象可能的类名或类，可省略
     * @returns 强转之后的Java Wrapper
     */
    export function getWrapper(jobj: Wrapper, cls: Wrapper | string = null): Wrapper {
        if (jobj == null) {
            Flog.e(_HELPER_TAG, `getWrapper() jobj == null`);
            return null;
        }
        try {
            cls = cls || jobj.$className;
            if (typeof cls === "string") {
                return Java.cast(jobj, Java.use(cls));
            } else {
                return Java.cast(jobj, cls);
            }
        } catch (error) {
            Flog.e(_HELPER_TAG, `getWrapper(${jobj}) ERROR:${error}`)
        }
        return null;
    }

    let _ClassClz: Wrapper;
    let _ObjectClz: Wrapper;

    /**
     * 通过Java对象Wrapper，拿到对象的全类名
     * @param {Wrapper} obj 未知对象
     * @returns 对象的全类名
     */
    export function getClsNameFromObj(obj: Wrapper): string {
        _ClassClz = _ClassClz || Java.use("java.lang.Class");
        _ObjectClz = _ObjectClz || Java.use("java.lang.Object");
        return _ClassClz.getName.call(_ObjectClz.getClass.call(obj));
    }

    /**
     * 获得App Context
     */
    export function getAppCtx() {
        let context = null;
        Java.perform(function () {
            let currentApplication = Java.use("android.app.ActivityThread").currentApplication();
            context = Java.retain(currentApplication.getApplicationContext());
        })
        return context;
    }

    /**
     * 通过反射来获取java对象 成员的值
     * @param {Wrapper} object java对象
     * @param {string} fieldName 字段名
     * @returns 对象成员的值或null
     */
    export function getFieldValue(object: Wrapper, fieldName: string): Wrapper {
        let field = object.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        let fieldValue = field.get(object);
        if (null === fieldValue) {
            Flog.w(_HELPER_TAG, `getFieldValue(${object.$className}, ${fieldName}) = NULL`);
            return null;
        }
        return getWrapper(fieldValue);
    }

    /**
     * 检查类名，过滤系统类和基本类型。返回false表示命中，需要过滤掉
     * @param name 类名
     * @returns boolean
     */
    function filterSysClass(name: string): boolean {
        return !(name.indexOf(".") < 0
            || name.startsWith("[")
            || name.startsWith("android")
            || name.startsWith("dalvik")
            || name.startsWith("kotlin")
            || name.startsWith("java")
            || name.startsWith("sun.")
            || name.startsWith("org.")
            || name.startsWith("com.android")
            || name.startsWith("com.google")
            || name.startsWith("libcore.")
            || name.startsWith("de.robv.android.xposed.")
        );
    }


    /**
     * 获得Java调用栈字符串
     */
    export function getStack(): string {
        let throwable = "";
        Java.perform(function () {
            throwable = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        });
        return throwable;
    }

    /**
     * 打印Java调用栈
     * @param TAG TAG，可选
     */
    export function printStack(TAG: string = ""): void {
        console.log("========================================  " + TAG + " Stack strat  ========================================");
        console.log(getStack());
        console.log("=========================================  " + TAG + " Stack end  =========================================\r\n");
    }

    /**
     * Hook（符合条件的）指定类的指定方法
     * @param clsFilterFunc 类过滤，不符合的(false)被过滤掉
     * @param methodFilterFunc 方法过滤，不符合的(false)被过滤掉
     * @param printStackFlag 是否打印调用栈
     */
    export function hookClsMethods(clsFilterFunc: (class_name: string) => boolean = null, methodFilterFunc: (method_name: string) => boolean = null, printStackFlag: boolean = false) {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                // class_name为加载的类名字符串
                onMatch: function (class_name: string, handle: NativePointer) {
                    if (!filterSysClass(class_name)) {
                        return;
                    }
                    if (clsFilterFunc && !clsFilterFunc(class_name)) {
                        return;
                    }
                    try {
                        let TargetClass: Wrapper = Java.use(class_name);
                        let methodsList: Wrapper[] = TargetClass.class.getDeclaredMethods();
                        Flog.d(_HOOK_TAG, `Hook ${class_name} has ${methodsList.length} methods.`);
                        methodsList.forEach((method) => {
                            let method_name = method.getName()
                            if (methodFilterFunc && !methodFilterFunc(method_name)) {
                                return;
                            }
                            hookMethodAllOverloads(class_name, method_name, printStackFlag);
                        })
                    } catch (error) {
                        Flog.d(_HOOK_TAG, `Hook ${class_name} failed, ERROR: ${error}`)
                    }

                },
                onComplete: function () {
                    Flog.i(_HOOK_TAG, "hookSomeClasses complete!!!")
                }
            })
        })
    }

    /**
     * 对某些类或包的所有方法进行hook
     * @param {String} whiteClsName 白名单
     * @param {String} blackClsName 黑名单，禁止出现的字符串
     * @param printStackFlag 是否打印调用栈，默认不打印
     */
    export function hookSomeClasses(whiteClsName: string, blackClsName: string = "", printStackFlag: boolean = false) {
        hookClsMethods((class_name) => {
            if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0)
                return false;
            if (whiteClsName.length == 0 && !filterSysClass(class_name))
                return false;
            return class_name.includes(whiteClsName);
        }, (method_name) => {
            return true;
        }, printStackFlag);
    }

    /**
     * 对某个特定的类的所有方法进行hook（拒绝搜索）
     * @param {string|Wrapper} cls 特定的类名、或者类Wrapper
     * @param printStackFlag 是否打印调用栈，默认不打印
     */
    export function hookSpecificClass(cls: string | Wrapper, printStackFlag: boolean = false) {
        Java.perform(function () {
            try {
                let TargetClass: Wrapper;
                if (typeof cls === "string") {
                    TargetClass = Java.use(cls);
                } else {
                    TargetClass = cls;
                }
                let methodsList: Wrapper[] = TargetClass.class.getDeclaredMethods();
                Flog.i(_HOOK_TAG, `Hook ${cls} has ${methodsList.length} methods.`);
                methodsList.forEach((method) => {
                    hookMethodAllOverloads(cls, method.getName(), printStackFlag);
                });
            } catch (error) {
                Flog.e(_HOOK_TAG, `hookSpecificClass failed: ${error}`)
            }
        })
    }

    /**
     * hook方法的每一个重载
     * @param {String|Wrapper} cls 要hook的类名
     * @param {String} methodName 要hook的方法名
     * @param printStackFlag 是否打印调用栈，默认不打印
     */
    export function hookMethodAllOverloads(cls: string | Wrapper, methodName: string, printStackFlag: boolean = false) {
        let overloadsLength = 0;
        Java.perform(function () {
            try {
                let clazz: Wrapper;
                if (typeof cls === "string") {
                    clazz = Java.use(cls);
                } else {
                    clazz = cls;
                }
                overloadsLength = clazz[methodName].overloads.length;
                for (let methodImp of clazz[methodName].overloads) {
                    methodImp.implementation = function () {
                        let checkNum = Math.floor(Math.random() * 90000) + 10000
                        let paramsStr = "";
                        // 遍历arguments
                        for (let j = 0; j < arguments.length; j++) {
                            let paramStr = ""
                            try {
                                paramStr = `${arguments[j].toString()}, `
                            } catch (e) {
                                paramStr = `${arguments[j]}, `
                            }
                            paramsStr += paramStr;
                        }
                        paramsStr = paramsStr.slice(0, -2)
                        if (printStackFlag) {
                            printStack(`${cls}.${methodName}-[${checkNum}]`)
                        } else {
                            Flog.i(_HOOK_TAG, `Called  ${cls}.${methodName}-[${checkNum}]`);
                        }
                        // 主动调用原方法获得结果
                        let result = this[methodName].apply(this, arguments);
                        // 打印参数以及结果
                        Flog.i(_HOOK_TAG, `Return  ${cls}.${methodName}-[${checkNum}](${paramsStr}) : ${result}`);
                        return result;
                    };
                }
            } catch (error) {
                Flog.w(`${cls}.${methodName}()hook failed:${error}`);
            }
            Flog.d(_HOOK_TAG, `\t ${cls}.${methodName}[${overloadsLength}] has hooked.`);
        });
    }

    /**
     * 获得[] Array数组的打印字符串
     * @param array Java任意数组[] 例如byte[]、int[]
     */
    export function toStrFromArray(array: any): string {
        // @ts-ignore
        return Java.use("java.util.Arrays").toString(array);
    }

    /**
     * 获得任意列表的打印字符串
     * @param list 任意列表 ArrayList等
     * @param separator 分隔符
     */
    export function toStrFromList(list: any, separator: string = "; "): string {
        let len = list.size();
        if (len < 1)
            return "[empty]"
        let logStr = "";
        for (let i = 0; i < len - 1; i++) {
            logStr += `[${i}]${list.get(i)}${separator}`;
        }
        logStr += `[${len - 1}]${list.get(len - 1)}`;
        return logStr;
    }

    /**
     * 获取Java Map转String的字符串
     * @param map Map变量
     * @param separator 分隔符
     */
    export function toStrFromMap(map: any, separator: string = "\n"): string {
        map = getWrapper(map);
        let logStr = "";
        let key_iterator = map.keySet().iterator();
        while (key_iterator.hasNext()) {
            let key = key_iterator.next();
            let value = map.get(key);
            logStr += `${key}:${value}${separator}`
        }
        logStr = logStr.slice(0, (0 - separator.length));
        return logStr
    }

    /**
     * 获取Java Set转String的字符串
     * @param set Set变量
     * @param separator 分隔符
     */
    export function toStrFromSet(set: any, separator: string = "\n"): string {
        set = getWrapper(set);
        let logStr = "";
        let iterator = set.iterator();
        let i = 0;
        while (iterator.hasNext()) {
            logStr += `[${i}]${iterator.next()}${separator}`;
            i++;
        }
        logStr = logStr.slice(0, (0 - separator.length));
        return set
    }

    /**
     * 调用Java实例的toString()方法
     * @param instance Java实例
     */
    export function toString(instance: Wrapper) {
        let logStr = `${instance}{  `
        let fields = instance.class.getDeclaredFields();
        fields.forEach(function (field) {
            try {
                field.setAccessible(true);
                var fieldName = field.getName();
                var fieldValue = field.get(instance);
                logStr += `${fieldName}=${fieldValue}, `
            } catch (e) {
                Flog.e("Error accessing field: " + field.getName() + " - " + e);
            }
        });
        logStr = logStr.slice(0, -2) + "  }"
        return logStr
    }

    /**
     * 打印[] Array数组
     * @param array 任意数组
     */
    export function printArray(array: any): void {
        Flog.i("printArray", toStrFromArray(array));
    }

    /**
     * 打印List列表
     * @param list 任意列表
     * @param separator 分隔符
     */
    export function printList(list: any, separator: string = "; "): void {
        Flog.i("printList", toStrFromList(list, separator));
    }

    /**
     * 打印JavaMap
     * @param map Map变量
     * @param separator 分隔符
     */
    export function printMap(map: any, separator: string = "\n"): void {
        Flog.i("printMap", toStrFromMap(map, separator));
    }

    /**
     * 打印Java Set数据
     * @param set Set变量
     * @param separator 分隔符
     */
    export function printSet(set: any, separator: string = "\n"): void {
        Flog.i("printSet", toStrFromSet(set, separator));
    }
}