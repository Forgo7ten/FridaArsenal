import {common} from "../common";
import {_Helper} from "./helper";
import Wrapper = Java.Wrapper;
import Flog = common.Flog;

export class _FindClazz {
    static readonly TAG: string = "FindClazz"

    /**
     * 寻找指定类的所有接口并打印
     * @param whiteClsName 要寻找接口的类名称
     * @param blackClsName 黑名单
     */
    static findAllInterfaces(whiteClsName: string, blackClsName: string = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name: string) {
                    // 对搜索范围进行限定
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    // 如果白名单为空（搜索全局），过滤一些系统类
                    if (whiteClsName.length == 0 && !_Helper.checkClass(class_name)) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        try {
                            let clazz: Wrapper = Java.use(class_name);
                            let interfaces: Wrapper[] = clazz.class.getInterfaces();
                            if (interfaces.length > 0) {
                                Flog.i(_FindClazz.TAG, `${class_name} [${interfaces.length}] :`);
                                interfaces.forEach((interface_name: Wrapper) => {
                                    Flog.i(_FindClazz.TAG, `\t ${interface_name.toString()}`)
                                })
                            }
                        } catch (error) {
                        }
                    }
                },
                onComplete: function () {
                    Flog.d(_FindClazz.TAG, `findAllInterfaces end.`);
                }
            })
        })
    }

    /**
     * 寻找指定类的所有父类并打印
     * @param whiteClsName 要寻找父类的类名称
     * @param blackClsName 黑名单
     */
    static findAllSuperclasses(whiteClsName: string, blackClsName: string = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name: string) {
                    // 对搜索范围进行限定
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    // 如果白名单为空（搜索全局），过滤一些系统类
                    if (whiteClsName.length == 0 && !_Helper.checkClass(class_name)) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        try {
                            let hook_cls: Wrapper = Java.use(class_name);
                            let superClass: Wrapper = hook_cls.class.getSuperclass();
                            Flog.i(_FindClazz.TAG, `${class_name} :`)
                            while (superClass != null) {
                                Flog.i(_FindClazz.TAG, `\t ${superClass.toString()}`);
                                superClass = superClass.getSuperclass();
                            }
                        } catch (error) {
                        }
                    }
                },
                onComplete: function () {
                    Flog.d(_FindClazz.TAG, `findAllSuperclasses end.`);
                }
            })
        })
    }


    /**
     * 通过提供的接口名称，在限定范围内查找实现类
     * @param interfaceName 要寻找实现类的接口名称
     * @param whiteClsName 白名单筛选
     * @param blackClsName 黑名单
     */
    static findImpByInterface(interfaceName: string, whiteClsName: string = "", blackClsName: string = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name: string) {
                    // 对搜索范围进行限定
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    // 如果白名单为空（搜索全局），过滤一些系统类
                    if (whiteClsName.length == 0 && !_Helper.checkClass(class_name)) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        try {
                            let clazz: Wrapper = Java.use(class_name);
                            let interfaces: Wrapper[] = clazz.class.getInterfaces();
                            if (interfaces.length > 0) {
                                interfaces.forEach((interface_name: Wrapper) => {
                                    if (interface_name.toString().indexOf(interfaceName) >= 0) {
                                        Flog.i(_FindClazz.TAG, `${class_name} :> ${interface_name.toString()}`);
                                    }
                                })
                            }
                        } catch (error) {
                        }
                    }
                },
                onComplete: function () {
                    Flog.d(_FindClazz.TAG, "findImpByInterface end");
                }
            })
        })
    }

    /**
     * 通过提供的父类名称，在限定范围内查找子类
     * @param superClassName 要寻找子类的父类名称
     * @param whiteClsName 白名单筛选
     * @param blackClsName 黑名单
     */
    static findChildBySuper(superClassName: string, whiteClsName: string = "", blackClsName: string = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name: string) {
                    // 对搜索范围进行限定
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    // 如果白名单为空（搜索全局），过滤一些系统类
                    if (whiteClsName.length == 0 && !_Helper.checkClass(class_name)) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        try {
                            let hook_cls: Wrapper = Java.use(class_name);
                            let superClass: Wrapper = hook_cls.class.getSuperclass();
                            while (superClass != null) {
                                if (superClass.toString().indexOf(superClassName) >= 0) {
                                    Flog.i(_FindClazz.TAG, `Found: ${class_name} -> ${superClass}`);
                                    break;
                                }
                                superClass = superClass.getSuperclass();
                            }
                        } catch (error) {
                        }
                    }
                },
                onComplete: function () {
                    Flog.d(_FindClazz.TAG, `findChildBySuper end.`);
                },
            });
        });
    }


}