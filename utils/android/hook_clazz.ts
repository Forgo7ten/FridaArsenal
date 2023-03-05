import {_Helper} from "./helper";
import {common} from "../common";
import Wrapper = Java.Wrapper;
import Flog = common.Flog;

export class _HookClazz {
    static readonly TAG: string = "HookClazz";


    /**
     * 对某些类或包的所有方法进行hook
     * @param {String} whiteClsName 白名单
     * @param {String} blackClsName 黑名单，禁止出现的字符串
     * @param printStack 是否打印调用栈，默认不打印
     */
    static hookSomeClasses(whiteClsName: string, blackClsName: string = "", printStack: boolean = false) {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                // class_name为加载的类名字符串
                onMatch: function (class_name: string, handle: NativePointer) {
                    // 可以通过包名限定需要处理的类名
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    if (whiteClsName.length == 0 && !_Helper.checkClass(class_name)) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        try {
                            let TargetClass: Wrapper = Java.use(class_name);
                            let methodsList: Wrapper[] = TargetClass.class.getDeclaredMethods();
                            Flog.d(_HookClazz.TAG, `Hook ${class_name} has ${methodsList.length} methods.`);
                            methodsList.forEach((method) => {
                                _HookClazz.hookMethodAllOverloads(class_name, method.getName(), printStack);
                            })
                        } catch (error) {
                            // Flog.e(_HookClazz.TAG, `hookSomeClasses failed: ${class_name}->${error}`)
                        }
                    }
                },
                onComplete: function () {
                    Flog.i(_HookClazz.TAG, "hookSomeClasses complete!!!")
                }
            })
        })
    }

    /**
     * 对某个特定的类的所有方法进行hook（拒绝搜索）
     * @param {*} clsName 特定的类名
     * @param printStack 是否打印调用栈，默认不打印
     */
    static hookSpecificClass(clsName: string, printStack: boolean = false) {
        Java.perform(function () {
            try {
                let TargetClass: Wrapper = Java.use(clsName);
                let methodsList: Wrapper[] = TargetClass.class.getDeclaredMethods();
                Flog.i(_HookClazz.TAG, `Hook ${clsName} has ${methodsList.length} methods.`);
                methodsList.forEach((method) => {
                    _HookClazz.hookMethodAllOverloads(clsName, method.getName(), printStack);
                });
            } catch (error) {
                Flog.e(_HookClazz.TAG, `hookSpecificClass failed: ${error}`)
            }
        })
    }

    /**
     * hook方法的每一个重载
     * @param {String} className 要hook的类名
     * @param {String} methodName 要hook的方法名
     * @param printStack 是否打印调用栈，默认不打印
     */
    static hookMethodAllOverloads(className: string, methodName: string, printStack: boolean = false) {
        let overloadsLength = 0;
        Java.perform(function () {
            try {
                let clazz: Wrapper = Java.use(className);
                overloadsLength = clazz[methodName].overloads.length;
                for (let methodImp of clazz[methodName].overloads) {
                    methodImp.implementation = function () {
                        // 主动调用原方法获得结果
                        let result = this[methodName].apply(this, arguments);
                        let paramStr = "";
                        // 遍历arguments
                        for (let j = 0; j < arguments.length; j++) {
                            if (j == arguments.length - 1) {
                                paramStr += arguments[j].toString();
                            } else {
                                paramStr += arguments[j].toString() + ",";
                            }
                        }
                        // 打印参数以及结果
                        Flog.i(_HookClazz.TAG, `Called ${className}.${methodName}(${paramStr}) : ${result}`);
                        if (printStack) {
                            _Helper.printStack(`${className}.${methodName}`)
                        }
                        return result;
                    };
                }
            } catch (error) {
                Flog.w(`${className}.${methodName}()hook failed:${error}`);
            }
            Flog.d(_HookClazz.TAG, `\t ${className}.${methodName}[${overloadsLength}] has hooked.`);
        });
    }
}