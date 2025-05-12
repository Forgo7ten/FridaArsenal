import {Flog} from "./Flog";
import Wrapper = Java.Wrapper;

/**
 * Android 帮助类
 */
export namespace AHelper {
    const _HOOK_TAG = "JAVA_HOOK"
    const _HELPER_TAG = "Helper"
    const _SEARCH_TAG = "Search"
    const _CAST_TAG = "Cast"
    const _CRYPTO_TAG = "Crypto";

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
     * 保存Gson对象Wrapper
     * @private
     */
    let _gson_obj: Wrapper | null = null;

    /**
     * 将对象转成json字符串
     * @param {object} obj 要转成json的对象
     * @returns json字符串
     */
    export function toGson(obj: Wrapper): string {
        try {
            if (_gson_obj == null) {
                Java.openClassFile("/data/local/tmp/fgson.dex").load();
                _gson_obj = Java.use('com.forgo7ten.gson.Gson');
            }
            return _gson_obj.$new().toJson(obj);
        } catch (error) {
            // md5sum fgson.dex: a7c58b60a7339e6a1207d5207c847bd5  fgson.dex
            Flog.e("toGson", `Please install the jar into the device first.\n  ERROR: ${error}`)
        }
    }

    /**
     * 字节数组转hex字符串 FixMe: writeS8 未测试
     * @param {*} array Wrapper数组
     * @param {*} off 偏移
     * @param {*} len 长度
     */
    export function toHexdump(array: Wrapper[], off: number, len: number) {
        off = off || 0;
        len = len || 0;
        len = len == 0 ? array.length : len;
        let ptr = Memory.alloc(len);
        for (let i = 0; i < len; ++i) {
            // @ts-ignore
            Memory.writeS8(ptr.add(i), array[i]);
        }
        return hexdump(ptr, {offset: off, length: len, header: false, ansi: false});
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
     * 打印 字节数组转hex字符串
     * @param {*} array Wrapper数组
     * @param {*} off 偏移
     * @param {*} len 长度
     */
    export function printHexdump(array: Wrapper[], off: number, len: number) {
        Flog.i(toHexdump(array, off, len))
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


    /**
     * 寻找指定类的所有接口并打印
     * @param whiteClsName 要寻找接口的类名称
     * @param blackClsName 黑名单
     */
    export function searchAllInterfaces(whiteClsName: string, blackClsName: string = "") {
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
    export function searchAllSuperclasses(whiteClsName: string, blackClsName: string = "") {
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
    export function searchImpByInterface(interfaceName: string, whiteClsName: string = "", blackClsName: string = "") {
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
    export function searchChildBySuper(superClassName: string, whiteClsName: string = "", blackClsName: string = "") {
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
    export function searchClassLoaderByHook(): void {
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
    export function searchClassLoaderSync(className: string): Wrapper | void {
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
    export function searchClassLoader(className: string, onCallback: () => void = () => {
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


    /**
     * FixMe: 未测试
     * dump客户端证书，并保存为p12的格式，证书密码为Forgo7ten
     */
    export function hook_keystore() {
        const TAG = "hook_keystore"
        let password = 'Forgo7ten';

        function getNowTime() {
            function dateFormat(fmt: string, date: Date) {
                let ret;
                const opt: { [key: string]: string } = {
                    "Y+": date.getFullYear().toString(),
                    "m+": (date.getMonth() + 1).toString(),
                    "d+": date.getDate().toString(),
                    "H+": date.getHours().toString(),
                    "M+": date.getMinutes().toString(),
                    "S+": date.getSeconds().toString()
                };
                for (let k in opt) {
                    ret = new RegExp("(" + k + ")").exec(fmt);
                    if (ret) {
                        fmt = fmt.replace(ret[1], (ret[1].length === 1) ? (opt[k]) : (opt[k].padStart(ret[1].length, "0")))
                    }

                }

                return fmt;
            }

            function random(min: number, max: number) {
                return Math.floor(Math.random() * (max - min)) + min;
            }

            return dateFormat("YYYY_mm_dd_HH_MM_SS", new Date()) + "_" + random(1, 100);
        }

        Java.perform(function () {
            function storeP12(privateKey: Wrapper, certificate: Wrapper, saveP12Path: string, p12Password: string) {
                let X509Certificate = Java.use("java.security.cert.X509Certificate")
                let p7X509 = Java.cast(certificate, X509Certificate);
                let chain = Java.array("java.security.cert.X509Certificate", [p7X509])
                let ks = Java.use("java.security.KeyStore").getInstance("PKCS12", "BC");
                ks.load(null, null);
                ks.setKeyEntry("client", privateKey, Java.use('java.lang.String').$new(p12Password).toCharArray(), chain);
                try {
                    let out = Java.use("java.io.FileOutputStream").$new(saveP12Path);
                    ks.store(out, Java.use('java.lang.String').$new(p12Password).toCharArray())
                } catch (error) {
                    Flog.e(TAG, `storeP12 error:${error}`)
                }
            }

            Java.use("java.security.KeyStore$PrivateKeyEntry").getPrivateKey.implementation = function () {
                let packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
                let savePath = '/sdcard/Download/' + packageName;

                let result = this.getPrivateKey();
                let fileName = savePath + getNowTime() + '.p12'
                storeP12(this.getPrivateKey(), this.getCertificate(), fileName, password);
                Flog.i(TAG, `dump ClinetCertificate => ${fileName} pwd: ${password}`);
                return result;
            }
            Java.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function () {
                let packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
                let savePath = '/sdcard/Download/' + packageName;
                let result = this.getCertificateChain()
                let fileName = savePath + getNowTime() + '.p12'
                storeP12(this.getPrivateKey(), this.getCertificate(), fileName, password);
                Flog.i(TAG, `dump ClinetCertificate => ${fileName} pwd: ${password}`);

                return result;
            }
        });
    }


    /**
     * 接受java的byte[]，将其转换成string并返回
     * ！！！禁止byte[]之外的类型
     * @param bytes java的byte[]数组
     * @return string 字节数组变为的字符串
     */
    export function cast_b2str(bytes: any): string {
        let array;
        try {
            array = Java.array("byte", bytes);
            return Java.use("java.lang.String").$new(array)
        } catch (error) {
            Flog.e(_CAST_TAG, `b2str(${bytes}) error: ${error}`)
            return null;
        }
    }

    /**
     * 接受java的byte[]，将其编码成base64字符串并返回
     * ！！！禁止byte[]之外的类型
     * @param bytes java的byte[]数组
     * @return string base64字符串
     */
    export function cast_b2b64str(bytes: any): string {
        let array;
        try {
            array = Java.array("byte", bytes)
            return Java.use("android.util.Base64")["encodeToString"](array, 0);
        } catch (error) {
            Flog.e(_CAST_TAG, `b2b64str(${bytes}) error: ${error}`)
            return null;
        }
    }

    /**
     * 接受java的byte[]，将其编码成hex字符串并返回
     * ！！！禁止byte[]之外的类型
     * @param bytes java的byte[]数组
     * @return string hex字符串
     */
    export function cast_b2hex(bytes: any): string {
        let array;
        try {
            array = Java.array("byte", bytes)
            return Java.use("com.android.okhttp.okio.ByteString").of(array).hex()
        } catch (error) {
            Flog.e(_CAST_TAG, `b2hex(${bytes}) error: ${error}`)
            return null;
        }
    }

    /**
     * 监听 Toast.show()方法
     */
    export function watchToast(): void {
        Java.perform(function () {
            let Toast = Java.use("android.widget.Toast");
            Toast.show.implementation = function () {
                let text = this.mText.value ? this.mText.value.toString() : "";
                printStack("SHOW Toast: " + text);
                return this.show();
            };
        });
    }

    /**
     * 监听弹窗
     */
    export function watchDialog(): void {
        let Dialog = Java.use("android.app.Dialog");
        Dialog["show"].implementation = function () {
            Flog.i(`${this} Dialog.show() is called`);
            printStack(`${this} Dialog.show()`)
            this["show"]();
        }
    }

    export function watchOnclick(): void {
        const TAG = "watchOnclick"

        function watch(obj: Wrapper, methodName: string) {
            let listener_name = getClsNameFromObj(obj);
            let target: Wrapper = Java.use(listener_name);
            if (!target || !(methodName in target)) {
                return;
            }
            target[methodName].overloads.forEach(function (overload: Java.Method) {
                overload.implementation = function () {
                    Flog.i(TAG, `${methodName}: ${getClsNameFromObj(this)}`);
                    return this[methodName].apply(this, arguments);
                };
            });
        }

        Java.perform(function () {
            // 以spawn的模式自启动的hook
            // HOOK View.onClick方法，监控
            Java.use("android.view.View").setOnClickListener.implementation = function (view: Wrapper) {
                if (view != null) {
                    watch(view, "onClick");
                }
                return this.setOnClickListener(view);
            };

            // attach模式去附加进程的hook，就是更慢的hook，需要看hook的时机，hook一些已有的东西
            Java.choose("android.view.View$ListenerInfo", {
                onMatch: function (instance) {
                    instance = instance.mOnClickListener.value;
                    if (instance) {
                        Flog.d(TAG, `mOnClickListener name is:${getClsNameFromObj(instance)}`);
                        watch(instance, "onClick");
                    }
                },
                onComplete: function () {
                }
            });
        });
    }

    /**
     * 监控MessageDigest类：md5,sha1,sha256...
     */
    export function watch_digest(printStackFlag = true): void {
        const MessageDigest_clazz = Java.use("java.security.MessageDigest");

        function hook_MessageDigest_update(printStackFlag) {
            const MessageDigest_update: Java.MethodDispatcher = MessageDigest_clazz["update"]
            const updateImpl: Java.MethodImplementation = function () {
                let input: Wrapper;
                let ret = this["update"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-MessageDigest", `${this}_${this.hashCode()}.update():${this.algorithm.value}`)
                if (arguments[0].$className != undefined) {
                    input = arguments[0].array();
                } else {
                    input = arguments[0]
                }
                let input_str: string
                if (typeof input === "number") {
                    input_str = `[byte 0x${(<number>input).toString(16)}]`
                } else {
                    input_str = cast_b2str(input)
                }
                if (input) Flog.i(_CRYPTO_TAG + "-MessageDigest", `input=${input}; input_str=${input_str}; input_b64=${cast_b2b64str(input)}`)
                if (printStackFlag) printStack("MessageDigest_update")
                return ret;
            }
            MessageDigest_update.overload('byte').implementation = updateImpl
            MessageDigest_update.overload('java.nio.ByteBuffer').implementation = updateImpl
            MessageDigest_update.overload('[B').implementation = updateImpl
            MessageDigest_update.overload('[B', 'int', 'int').implementation = updateImpl

        }

        function hook_MessageDigest_digest(printStackFlag) {
            const MessageDigest_digest: Java.MethodDispatcher = MessageDigest_clazz["digest"]
            const digestImpl: Java.MethodImplementation = function () {
                let output: Wrapper | null;
                let ret = this["digest"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-MessageDigest", `${this}_${this.hashCode()}.digest():${this.algorithm.value}`)
                switch (arguments.length) {
                    case 0:
                        output = ret;
                        break;
                    case 3:
                        output = arguments[0];
                        break;
                    default:
                        output = null;
                        break;
                }
                if (output) Flog.i(_CRYPTO_TAG + "-MessageDigest", `output=${output}; output_hex=${cast_b2hex(output)}`)
                if (printStackFlag) printStack("MessageDigest_digest")
                return ret;
            }

            MessageDigest_digest.overload().implementation = digestImpl
            // 会调用第一个重载
            // MessageDigest_digest.overload('[B').implementation = digestImpl
            MessageDigest_digest.overload('[B', 'int', 'int').implementation = digestImpl

        }

        Java.perform(() => {
            hook_MessageDigest_update(printStackFlag);
            hook_MessageDigest_digest(printStackFlag);
        })
    }

    /**
     * 监控Cipher类：AES,DES,RSA...
     */
    export function watch_cipher(need_printStack = false): void {
        const Cipher_clazz = Java.use("javax.crypto.Cipher");

        function hook_Cipher_init(printStackFlag) {
            const Cipher_chooseProvider: Java.MethodDispatcher = Cipher_clazz["chooseProvider"]
            const IvParameterSpec_clazz = Java.use("javax.crypto.spec.IvParameterSpec")
            /**
             * Cipher.init() 方法的深层次函数，所有的init最终都会执行该方法
             */
            Cipher_chooseProvider.implementation = function (initType: Wrapper, opmode: number, key: Wrapper, paramSpec: Wrapper, params: Wrapper, random: Wrapper) {
                let opmode_str: string = this["getOpmodeString"](opmode);
                Flog.line(_CRYPTO_TAG + "-Cipher", `${this}.init(): ${this.transformation.value} -> ${opmode_str}`)
                if (null != key) {
                    let key_algorithm = key["getAlgorithm"]();
                    let key_format = key["getFormat"]();
                    let key_encoded = key["getEncoded"]();
                    Flog.i(_CRYPTO_TAG + "-Cipher", `Key info: algorithm=${key_algorithm}; format=${key_format}; encoded=${key_encoded}; key_str=${cast_b2str(key_encoded)}; key_b64=${cast_b2b64str(key_encoded)}`)
                }
                if (paramSpec != null) {
                    try {
                        paramSpec = Java.cast(paramSpec, IvParameterSpec_clazz)
                        let iv = paramSpec.getIV()
                        Flog.i(_CRYPTO_TAG + "-Cipher", `IV=${iv}; IV_str=${cast_b2str(iv)}`)
                    } catch (error) {
                        Flog.i(_CRYPTO_TAG + "-Cipher", `paramSpec=${paramSpec.toString()}`)
                    }
                }
                let ret = this["chooseProvider"].apply(this, arguments)
                // console.warn(_WatchCipher.TAG, `${this} -> ${this.spi.value}`)
                if (printStackFlag) printStack("Cipher_init")
                return ret;
            };
        }

        function hook_Cipher_update(printStackFlag) {
            const Cipher_update: Java.MethodDispatcher = Cipher_clazz["update"]
            const updateImpl: Java.MethodImplementation = function () {
                let input: Wrapper | null;
                let output: Wrapper | null;
                let ret = this["update"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-Cipher", `${this}.update():${this.transformation.value}`)
                if (arguments.length == 2) {
                    // .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
                    input = arguments[0].array();
                    output = arguments[1].array();
                } else if (arguments.length <= 3) {
                    // .overload('[B')
                    // .overload('[B', 'int', 'int').
                    input = arguments[0];
                    output = ret;
                } else {
                    // arguments.length > 3
                    // .overload('[B', 'int', 'int', '[B')
                    // .overload('[B', 'int', 'int', '[B', 'int')
                    input = arguments[0];
                    output = arguments[3];
                }
                if (input) Flog.i(_CRYPTO_TAG + "-Cipher", `input=${input}; input_str=${cast_b2str(input)}; input_b64=${cast_b2b64str(input)}`)
                if (output) Flog.i(_CRYPTO_TAG + "-Cipher", `output=${output}; output_hex=${cast_b2hex(output)}; output_b64=${cast_b2b64str(output)}`)
                if (printStackFlag) printStack("Cipher_update")
                return ret;
            }

            Cipher_update.overload('[B').implementation = updateImpl;
            Cipher_update.overload('[B', 'int', 'int').implementation = updateImpl;
            Cipher_update.overload('[B', 'int', 'int', '[B').implementation = updateImpl;
            Cipher_update.overload('[B', 'int', 'int', '[B', 'int').implementation = updateImpl;
            Cipher_update.overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer').implementation = updateImpl;
        }

        function hook_Cipher_doFinal(printStackFlag) {
            const Cipher_doFinal: Java.MethodDispatcher = Cipher_clazz["doFinal"];

            /**
             * FixMe: 没有经过详细的测试
             */
            const doFinalImpl: Java.MethodImplementation = function () {
                let input: Wrapper | null;
                let output: Wrapper | null;
                let ret = this["doFinal"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-Cipher", `${this}.doFinal():${this.transformation.value}`)
                if ([0, 1, 3].includes(arguments.length)) {
                    // .overload()
                    // .overload('[B')
                    // .overload('[B', 'int', 'int').
                    input = arguments[0];
                    output = ret;
                } else if (arguments.length > 3) {
                    // .overload('[B', 'int', 'int', '[B')
                    // .overload('[B', 'int', 'int', '[B', 'int')
                    input = arguments[0];
                    output = arguments[3];
                } else {
                    if (arguments[0].$className === undefined) {
                        // .overload('[B', 'int')
                        input = null;
                        output = arguments[0];
                    } else {
                        // .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
                        input = arguments[0].array();
                        output = arguments[1].array();
                    }
                }
                if (input) Flog.i(_CRYPTO_TAG + "-Cipher", `input=${input}; input_str=${cast_b2str(input)}; input_b64=${cast_b2b64str(input)}`)
                if (output) Flog.i(_CRYPTO_TAG + "-Cipher", `output=${output}; output_hex=${cast_b2hex(output)}; output_b64=${cast_b2b64str(output)}`)
                if (printStackFlag) printStack("Cipher_doFinal")
                return ret;
            }

            Cipher_doFinal.overload().implementation = doFinalImpl
            Cipher_doFinal.overload('[B').implementation = doFinalImpl
            Cipher_doFinal.overload('[B', 'int').implementation = doFinalImpl
            Cipher_doFinal.overload('[B', 'int', 'int').implementation = doFinalImpl
            Cipher_doFinal.overload('[B', 'int', 'int', '[B').implementation = doFinalImpl
            Cipher_doFinal.overload('[B', 'int', 'int', '[B', 'int').implementation = doFinalImpl
            Cipher_doFinal.overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer').implementation = doFinalImpl

        }

        Java.perform(() => {
            hook_Cipher_init(need_printStack);
            hook_Cipher_update(need_printStack);
            hook_Cipher_doFinal(need_printStack);
        })
    }


    /**
     * 监控hmac系列加解密
     */
    export function watch_mac(need_printStack = false): void {
        const Mac_clazz = Java.use("javax.crypto.Mac");

        function hook_Mac_init(printStackFlag) {
            const Mac_init: Java.MethodDispatcher = Mac_clazz["init"]
            const IvParameterSpec_clazz = Java.use("javax.crypto.spec.IvParameterSpec")
            const initImpl: Java.MethodImplementation = function () {
                let paramSpec: Wrapper;
                let ret = this["init"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-Hmac", `${this}.init():${this.algorithm.value}`)
                let key: Wrapper = arguments[0];
                let key_algorithm = key["getAlgorithm"]();
                let key_format = key["getFormat"]();
                let key_encoded = key["getEncoded"]();
                if (key) Flog.i(_CRYPTO_TAG + "-Hmac", `Key info: algorithm=${key_algorithm}; format=${key_format}; encoded=${key_encoded}; key_str=${cast_b2str(key_encoded)}; key_b64=${cast_b2b64str(key_encoded)}`)
                if (arguments.length == 2) {
                    // .overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec')
                    paramSpec = arguments[1];
                    try {
                        paramSpec = Java.cast(paramSpec, IvParameterSpec_clazz);
                        let iv = paramSpec.getIV();
                        Flog.i(_CRYPTO_TAG + "-Cipher", `IV=${iv}; IV_str=${cast_b2str(iv)}`);
                    } catch (error) {
                        Flog.i(_CRYPTO_TAG + "-Cipher", `paramSpec=${paramSpec.toString()}`);
                    }
                }
                if (printStackFlag) printStack("Mac_init")
                return ret;
            }
            Mac_init.overload('java.security.Key').implementation = initImpl
            Mac_init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = initImpl

        }

        function hook_Mac_update(printStackFlag) {
            const Mac_update: Java.MethodDispatcher = Mac_clazz["update"];
            const updateImpl: Java.MethodImplementation = function () {
                let input: Wrapper;
                let ret = this["update"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-Hmac", `${this}.update():${this.algorithm.value}`)
                if (arguments[0].$className != undefined) {
                    input = arguments[0].array();
                } else {
                    input = arguments[0];
                }
                let input_str: string
                if (typeof input === "number") {
                    input_str = `[byte 0x${(<number>input).toString(16)}]`
                } else {
                    input_str = cast_b2str(input)
                }
                if (input) Flog.i(_CRYPTO_TAG + "-Hmac", `input=${input}; input_str=${input_str}; input_b64=${cast_b2b64str(input)}`)
                if (printStackFlag) printStack("Mac_update")
                return ret;
            }

            Mac_update.overload('byte').implementation = updateImpl;
            Mac_update.overload('java.nio.ByteBuffer').implementation = updateImpl;
            Mac_update.overload('[B').implementation = updateImpl;
            Mac_update.overload('[B', 'int', 'int').implementation = updateImpl;

        }

        function hook_Mac_doFinal(printStackFlag) {
            const Mac_doFinal: Java.MethodDispatcher = Mac_clazz["doFinal"]
            const doFinalImpl: Java.MethodImplementation = function () {
                let output: Wrapper | null;
                let ret = this["doFinal"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-Hmac", `${this}.doFinal():${this.algorithm.value}`)
                switch (arguments.length) {
                    case 0:
                        output = ret;
                        break;
                    case 2:
                        output = arguments[0];
                        break;
                    default:
                        output = null;
                        break;
                }
                if (output) Flog.i(_CRYPTO_TAG + "-Hmac", `output=${output}; output_hex=${cast_b2hex(output)}`)
                if (printStackFlag) printStack("Mac_doFinal")
                return ret;
            }


            Mac_doFinal.overload().implementation = doFinalImpl
            // Mac_doFinal.overload('[B').implementation = doFinalImpl
            Mac_doFinal.overload('[B', 'int').implementation = doFinalImpl

        }

        Java.perform(() => {
            hook_Mac_init(need_printStack);
            hook_Mac_update(need_printStack);
            hook_Mac_doFinal(need_printStack);
        })
    }

    /**
     * 监控密码加解密相关方法
     * @param stack 控制调用栈的打印，默认为true，打印调用栈
     */
    export function watch_crypto(stack: boolean = true): void {
        Java.perform(() => {
            watch_cipher(stack);
            watch_digest(stack);
            watch_mac(stack);
        })
    }

}