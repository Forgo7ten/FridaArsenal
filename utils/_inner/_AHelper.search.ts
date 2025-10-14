import Wrapper = Java.Wrapper;
import {Flog} from "../Flog";
import {_AHelperCore} from "./_AHelper.core";

const {filterSysClass} = _AHelperCore
export const _AHelperSearch = (() => {
    const _SEARCH_TAG = "Search"

    /**
     * 寻找指定类的所有接口并打印
     * @param whiteClsName 要寻找接口的类名称
     * @param blackClsName 黑名单
     */
    function searchAllInterfaces(whiteClsName: string, blackClsName: string = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name: string) {
                    // 对搜索范围进行限定
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    // 如果白名单为空（搜索全局），过滤一些系统类
                    if (whiteClsName.length == 0 && !filterSysClass(class_name)) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        try {
                            let clazz: Wrapper = Java.use(class_name);
                            let interfaces: Wrapper[] = clazz.class.getInterfaces();
                            if (interfaces.length > 0) {
                                Flog.i(_SEARCH_TAG, `${class_name} [${interfaces.length}] :`);
                                interfaces.forEach((interface_name: Wrapper) => {
                                    Flog.i(_SEARCH_TAG, `\t ${interface_name.toString()}`)
                                })
                            }
                        } catch (error) {
                        }
                    }
                },
                onComplete: function () {
                    Flog.d(_SEARCH_TAG, `searchAllInterfaces end.`);
                }
            })
        })
    }

    /**
     * 寻找指定类的所有父类并打印
     * @param whiteClsName 要寻找父类的类名称
     * @param blackClsName 黑名单
     */
    function searchAllSuperclasses(whiteClsName: string, blackClsName: string = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name: string) {
                    // 对搜索范围进行限定
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    // 如果白名单为空（搜索全局），过滤一些系统类
                    if (whiteClsName.length == 0 && !filterSysClass(class_name)) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        try {
                            let hook_cls: Wrapper = Java.use(class_name);
                            let superClass: Wrapper = hook_cls.class.getSuperclass();
                            Flog.i(_SEARCH_TAG, `${class_name} :`)
                            while (superClass != null) {
                                Flog.i(_SEARCH_TAG, `\t ${superClass.toString()}`);
                                superClass = superClass.getSuperclass();
                            }
                        } catch (error) {
                        }
                    }
                },
                onComplete: function () {
                    Flog.d(_SEARCH_TAG, `searchAllSuperclasses end.`);
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
    function searchImpByInterface(interfaceName: string, whiteClsName: string = "", blackClsName: string = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name: string) {
                    // 对搜索范围进行限定
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    // 如果白名单为空（搜索全局），过滤一些系统类
                    if (whiteClsName.length == 0 && !filterSysClass(class_name)) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        try {
                            let clazz: Wrapper = Java.use(class_name);
                            let interfaces: Wrapper[] = clazz.class.getInterfaces();
                            if (interfaces.length > 0) {
                                interfaces.forEach((interface_name: Wrapper) => {
                                    if (interface_name.toString().indexOf(interfaceName) >= 0) {
                                        Flog.i(_SEARCH_TAG, `${class_name} :> ${interface_name.toString()}`);
                                    }
                                })
                            }
                        } catch (error) {
                        }
                    }
                },
                onComplete: function () {
                    Flog.d(_SEARCH_TAG, "searchImpByInterface end");
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
    function searchChildBySuper(superClassName: string, whiteClsName: string = "", blackClsName: string = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name: string) {
                    // 对搜索范围进行限定
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    // 如果白名单为空（搜索全局），过滤一些系统类
                    if (whiteClsName.length == 0 && !filterSysClass(class_name)) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        try {
                            let hook_cls: Wrapper = Java.use(class_name);
                            let superClass: Wrapper = hook_cls.class.getSuperclass();
                            while (superClass != null) {
                                if (superClass.toString().indexOf(superClassName) >= 0) {
                                    Flog.i(_SEARCH_TAG, `Found: ${class_name} -> ${superClass}`);
                                    break;
                                }
                                superClass = superClass.getSuperclass();
                            }
                        } catch (error) {
                        }
                    }
                },
                onComplete: function () {
                    Flog.d(_SEARCH_TAG, `searchChildBySuper end.`);
                },
            });
        });
    }


    /**
     * 通过hook的方式来获取classloader，并设置
     */
    function searchClassLoaderByHook(): void {
        let ActivityThread_clazz = Java.use("android.app.ActivityThread");
        ActivityThread_clazz["performLaunchActivity"].implementation = function () {
            let ret: Wrapper = this["performLaunchActivity"].apply(this, arguments);
            // @ts-ignore
            Java.classFactory.loader = this.mInitialApplication.value.getClassLoader();
            return ret;
        }
    }

    /**
     * 同步的方式来寻找classloader
     * @param {String} className 尝试加载的类
     */
    function searchClassLoaderSync(className: string): Wrapper | void {
        if (className == undefined) {
            Flog.e(_SEARCH_TAG, "className == undefined, return.");
            return;
        }
        let clsLoaders: Wrapper[] = Java.enumerateClassLoadersSync();
        for (let loader of clsLoaders) {
            try {
                // 如果找到的类加载器 能加载的类有[className]
                if (loader.findClass(className)) {
                    Flog.i(_SEARCH_TAG, "Successfully found loader.");
                    // @ts-ignore
                    Java.classFactory.loader = loader;
                    return loader;
                }
            } catch (error) {
            }
        }
        Flog.d(_SEARCH_TAG, "searchClassLoaderSync End.");
    }


    /**
     * 异步的方式来寻找classloader，之后调用回调函数
     * @param className 尝试加载的类
     * @param onCallback 寻找到ClassLoader之后要回调的函数，默认为空
     */
    function searchClassLoader(className: string, onCallback: () => void = () => {
    }): void {
        let found: boolean = false;
        if (className == undefined) {
            Flog.w(_SEARCH_TAG, "className == undefined, return.");
            return;
        }
        // 枚举内存中的 类加载器
        Java.enumerateClassLoaders({
            onMatch: function (loader: Wrapper) {
                try {
                    if (found) return;
                    // Flog.d(_SEARCH_TAG, `Found loader: ${loader}`)
                    // 如果找到的类加载器 能加载的类有[class_name]//
                    if (loader.findClass(className)) {
                        // @ts-ignore
                        Java.classFactory.loader = loader;
                        onCallback();
                        Flog.i(_SEARCH_TAG, "Successfully found loader.");
                        found = true;
                    }
                } catch (error) {
                }
            },
            onComplete: function () {
                Flog.d(_SEARCH_TAG, "searchClassLoader End.");
            },
        });
    }

    return {
        searchAllInterfaces,
        searchAllSuperclasses,
        searchImpByInterface,
        searchChildBySuper,
        searchClassLoaderByHook,
        searchClassLoaderSync,
        searchClassLoader,
    };
})()