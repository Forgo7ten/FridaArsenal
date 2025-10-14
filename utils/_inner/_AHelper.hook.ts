import Wrapper = Java.Wrapper;
import {Flog} from "../Flog";
import {_AHelperCore} from "./_AHelper.core";

const {filterSysClass, printStack} = _AHelperCore
export const _AHelperHook = (() => {
    const _HOOK_TAG = "JAVA_HOOK"

    /**
     * Hook（符合条件的）指定类的指定方法
     * @param clsFilterFunc 类过滤，不符合的(false)被过滤掉
     * @param methodFilterFunc 方法过滤，不符合的(false)被过滤掉
     * @param printStackFlag 是否打印调用栈
     */
    function hookClsMethods(clsFilterFunc: (class_name: string) => boolean = null, methodFilterFunc: (method_name: string) => boolean = null, printStackFlag: boolean = false) {
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
    function hookSomeClasses(whiteClsName: string, blackClsName: string = "", printStackFlag: boolean = false) {
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
    function hookSpecificClass(cls: string | Wrapper, printStackFlag: boolean = false) {
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
    function hookMethodAllOverloads(cls: string | Wrapper, methodName: string, printStackFlag: boolean = false) {
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
     * FixMe: 未测试
     * dump客户端证书，并保存为p12的格式，证书密码为Forgo7ten
     */
    function hook_keystore() {
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


    return {
        hookClsMethods,
        hookSomeClasses,
        hookSpecificClass,
        hookMethodAllOverloads,
        hook_keystore,
    };

})()