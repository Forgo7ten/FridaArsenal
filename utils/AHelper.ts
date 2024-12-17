import {Flog} from "./Flog";
import Wrapper = Java.Wrapper;

export namespace AHelper {
    const _JAVA_HOOK_TAG = "JAVA_HOOK"

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
                        Flog.d(_JAVA_HOOK_TAG, `Hook ${class_name} has ${methodsList.length} methods.`);
                        methodsList.forEach((method) => {
                            let method_name = method.getName()
                            if (methodFilterFunc && !methodFilterFunc(method_name)) {
                                return;
                            }
                            hookMethodAllOverloads(class_name, method_name, printStackFlag);
                        })
                    } catch (error) {
                        Flog.d(_JAVA_HOOK_TAG, `Hook ${class_name} failed, ERROR: ${error}`)
                    }

                },
                onComplete: function () {
                    Flog.i(_JAVA_HOOK_TAG, "hookSomeClasses complete!!!")
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
                Flog.i(_JAVA_HOOK_TAG, `Hook ${cls} has ${methodsList.length} methods.`);
                methodsList.forEach((method) => {
                    hookMethodAllOverloads(cls, method.getName(), printStackFlag);
                });
            } catch (error) {
                Flog.e(_JAVA_HOOK_TAG, `hookSpecificClass failed: ${error}`)
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
                            Flog.i(_JAVA_HOOK_TAG, `Called  ${cls}.${methodName}-[${checkNum}]`);
                        }
                        // 主动调用原方法获得结果
                        let result = this[methodName].apply(this, arguments);
                        // 打印参数以及结果
                        Flog.i(_JAVA_HOOK_TAG, `Return  ${cls}.${methodName}-[${checkNum}](${paramsStr}) : ${result}`);
                        return result;
                    };
                }
            } catch (error) {
                Flog.w(`${cls}.${methodName}()hook failed:${error}`);
            }
            Flog.d(_JAVA_HOOK_TAG, `\t ${cls}.${methodName}[${overloadsLength}] has hooked.`);
        });
    }
}