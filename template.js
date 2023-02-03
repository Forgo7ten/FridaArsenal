function main1() {
    Java.perform(() => {
        // hello
    })
    console.warn("Done!")
}


function main() {
    // 添加逻辑
    main1();
}

















/********************========== 分割线 ==========********************/

let futil = {
    /**
     * 寻找指定类的所有接口并打印
     * @param {String} whiteClsName 要寻找接口的类名称
     * @param {String} blackClsName 黑名单
     */
    findAllInterfaces: function findAllInterfaces(whiteClsName, blackClsName = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name) {
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        var clazz = Java.use(class_name);
                        var interfaces = clazz.class.getInterfaces();
                        if (interfaces.length > 0) {
                            console.log(class_name, ":");
                            for (var i in interfaces) {
                                console.log("\t", interfaces[i].toString())
                            }
                        }
                    }
                },
                onComplete: function () {
                    console.log("findAllInterfaces end");
                }
            })
        })
    },
    /**
     * 寻找指定类的所有父类并打印
     * @param {String} whiteClsName 要寻找父类的类名称
     * @param {String} blackClsName 黑名单
     */
    findAllSuperclasses: function findAllSuperclasses(whiteClsName, blackClsName = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name) {
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        var hook_cls = Java.use(class_name);
                        var superClass = hook_cls.class.getSuperclass();
                        console.log(class_name, ":")
                        while (superClass != null) {
                            console.log("\t", superClass.toString());
                            superClass = superClass.getSuperclass();
                        }
                    }
                },
                onComplete: function () {
                    console.log("findAllSuperclasses end");
                }
            })
        })
    },


    /**
     * 通过提供的父类名称，在限定范围内查找子类
     * @param {String} whiteClsName 白名单筛选
     * @param {String} superClassName 要寻找子类的父类名称
     * @param {String} blackClsName 黑名单
     */
    findChildBySuper: function findChildBySuper(whiteClsName, superClassName, blackClsName = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name) {
                    // 对搜索范围进行限定
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        var hook_cls = Java.use(class_name);
                        var superClass = hook_cls.class.getSuperclass();
                        while (superClass != null) {
                            if (superClass.toString().indexOf(superClassName) >= 0) {
                                console.log("Found:", class_name, superClass);
                            }
                            superClass = superClass.getSuperclass();
                        }
                    }
                },
                onComplete: function () {
                    console.log("findChildBySuper end");
                },
            });
        });
    },


    /**
     * 通过提供的接口名称，在限定范围内查找实现类
     * @param {String} whiteClsName 白名单筛选
     * @param {String} interfaceName 要寻找实现类的接口名称
     * @param {String} blackClsName 黑名单
     */
    findImpByInterface: function findImpByInterface(whiteClsName, interfaceName, blackClsName = "") {
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (class_name) {
                    // 对搜索范围进行限定
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    if (class_name.indexOf(whiteClsName) >= 0) {
                        var clazz = Java.use(class_name);
                        var interfaces = clazz.class.getInterfaces();
                        if (interfaces.length > 0) {
                            for (var i in interfaces) {
                                if (interfaces[i].toString().indexOf(interfaceName) >= 0) {
                                    console.log(class_name, ":", interfaces[i].toString());
                                }
                            }
                        }
                    }
                },
                onComplete: function () {
                    console.log("findImpByInterface end");
                }
            })
        })
    },

    /**
     * 通过hook的方式来获取classloader，并设置
     */
    findClassLoaderByHook: function findClassLoaderByHook() {
        let ActivityThread_clazz = Java.use("android.app.ActivityThread");
        ActivityThread_clazz["performLaunchActivity"].implementation = function () {
            let ret = this["performLaunchActivity"].apply(this, arguments);
            Java.classFactory.loader = this.mInitialApplication.value.getClassLoader();
            return ret;
        }
    },

    /**
     * 同步的方式来寻找classloader
     * @param {String} className 尝试加载的类
     */
    findClassLoaderSync: function findClassLoaderSync(className) {
        Java.perform(() => {
            if (className == undefined) {
                console.warn("className==undefined, return");
                return;
            }
            let clsLoaders = Java.enumerateClassLoadersSync();
            for (let loader of clsLoaders) {
                try {
                    // 如果找到的类加载器 能加载的类有[className]
                    if (loader.findClass(className)) {
                        console.log("Successfully found loader");
                        // 设置 java默认的classloader
                        Java.classFactory.loader = loader;
                        // console.log(loader);
                    }
                } catch (error) {
                    // console.log("error:" + error);
                }
            }
        })
    },

    /**
     * 异步的方式来寻找classloader，之后调用回调函数
     * @param {String} className 尝试加载的类
     * @param {*} callback 回调函数
     */
    findClassLoader: function findClassLoader(className, callback = () => { }) {
        Java.perform(function () {
            if (className == undefined) {
                console.warn("className==undefined, return");
                return;
            }
            // 枚举内存中的 类加载器
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        // 如果找到的类加载器 能加载的类有[class_name]
                        if (loader.findClass(className)) {
                            console.log("Successfully found loader");
                            // 设置 java默认的classloader
                            Java.classFactory.loader = loader;
                            // console.log(loader);
                        }
                    } catch (error) {
                        // console.log("find error:" + error);
                    }
                },
                onComplete: function () {
                    console.log("End");
                },
            });
            // 再 使用该类
            callback();
        });
    },

    getContext: function getContext() {
        let context = null;
        Java.perform(function () {
            var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
            context = Java.retain(currentApplication.getApplicationContext());
            // console.log(context);
            /* var packageName = context.getPackageName();
            console.log(packageName);
            console.log(currentApplication.getPackageName()); */
        })
        return context;
    },

    /**
     * 对某些类或包的所有方法进行hook
     * @param {String} whiteClsName 白名单
     * @param {String} blackClsName 黑名单，禁止出现的字符串
     */
    hookSomeClasses: function hookSomeClasses(whiteClsName, blackClsName = "") {
        let thiz = this;
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                // name为加载的类名字符串
                onMatch: function (name, handle) {
                    // 可以通过包名限定需要处理的类名
                    if (blackClsName.length != 0 && class_name.indexOf(blackClsName) >= 0) {
                        return;
                    }
                    if (name.indexOf(whiteClsName) >= 0) {
                        console.log(name, handle); // 打印handle
                        // 利用反射 获取类中的所有方法
                        var TargetClass = Java.use(name);
                        // return Method Object List
                        var methodsList = TargetClass.class.getDeclaredMethods();
                        for (var i = 0; i < methodsList.length; i++) {
                            // console.log(methodsList[i].getName()); // 打印其中方法的名字
                            // 可以hook该类中的所有方法
                            thiz.hookMethodAllOverloads(name, methodsList[i].getName());
                        }
                    }
                },
                onComplete: function () {
                    console.log("enumerateLoadedClasses complete!!!")
                }
            })
        })
    },

    /**
     * 对某个特定的类的所有方法进行hook（拒绝搜索）
     * @param {*} clsName 特定的类名
     */
    hookSpecificClass: function hookSpecificClass(clsName) {
        let thiz = this;
        Java.perform(function () {
            console.log("Hook class:", clsName);
            // 利用反射 获取类中的所有方法
            var TargetClass = Java.use(clsName);
            // return Method Object List
            var methodsList = TargetClass.class.getDeclaredMethods();
            for (var i = 0; i < methodsList.length; i++) {
                // console.log(methodsList[i].getName()); // 打印其中方法的名字
                // 可以hook该类中的所有方法
                thiz.hookMethodAllOverloads(clsName, methodsList[i].getName());
            }
        })
    },

    /**
     * hook方法的每一个重载
     * @param {String} className 要hook的类名
     * @param {String} methodName 要hook的方法名
     */
    hookMethodAllOverloads: function hookMethodAllOverloads(className, methodName) {
        Java.perform(function () {
            // hook 指定方法的所有重载
            var clazz = Java.use(className);
            // Object.toString同Object["toString"]
            try {
                var overloadsLength = clazz[methodName].overloads.length;
            } catch (error) {
                console.warn(className + "." + methodName, "hook failed:", error);
            }
            for (var i = 0; i < overloadsLength; i++) {
                clazz[methodName].overloads[i].implementation = function () {
                    // 主动调用原方法获得结果
                    var result = this[methodName].apply(this, arguments);
                    var paramStr = "";
                    // 遍历arguments
                    for (var j = 0; j < arguments.length; j++) {
                        if (j == arguments.length - 1) {
                            paramStr += arguments[j];
                        } else {
                            paramStr += arguments[j] + ",";
                        }
                    }
                    // 打印参数以及结果
                    console.log("Called", className + "." + methodName + "(" + paramStr + ") :", result);
                    // 调用原方法
                    return result;
                };
            }
            console.log("[" + overloadsLength + "]", className + "." + methodName, "Hooked!");
        });
    },

    printStack: function printStack(name = "") {
        Java.perform(function () {
            var throwable = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
            console.log("=============================" + name + " Stack strat=======================");
            console.log(throwable);
            console.log("=============================" + name + " Stack end=======================\r\n");
        });
    },

    __inner_gson_init_flag: false,
    /**
     * 将对象转成json
     * @param {object} obj 要转成json的对象
     * @returns json字符串
     */
    toGson: function toGson(obj) {
        if (!this.__inner_gson_init_flag) {
            Java.openClassFile("/data/local/tmp/r0gson.dex").load();
            this.__inner_gson_init_flag = true;
        }
        const gson = Java.use('com.r0ysue.gson.Gson');
        return gson.$new().toJson(obj);
    },

    __inner_jclazz: null,
    __inner_jobj: null,
    /**
     * 通过对象，拿到对象的全类名
     * @param {*} obj 未知对象
     * @returns 对象的全类名
     */
    getObjClassName: function getObjClassName(obj) {
        if (!__inner_jclazz) {
            var __inner_jclazz = Java.use("java.lang.Class");
        }
        if (!__inner_jobj) {
            var __inner_jobj = Java.use("java.lang.Object");
        }
        return __inner_jclazz.getName.call(__inner_jobj.getClass.call(obj));
    },

    /**
     * [未测试] dump客户端证书，并保存为p12的格式，证书密码为Forgo7ten
     */
    hook_keystore: function hook_keystore() {
        var password = 'Forgo7ten';

        function getNowTime() {
            function dateFormat(fmt, date) {
                let ret;
                const opt = { "Y+": date.getFullYear().toString(), "m+": (date.getMonth() + 1).toString(), "d+": date.getDate().toString(), "H+": date.getHours().toString(), "M+": date.getMinutes().toString(), "S+": date.getSeconds().toString() };
                for (let k in opt) {
                    ret = new RegExp("(" + k + ")").exec(fmt);
                    if (ret) {
                        fmt = fmt.replace(ret[1], (ret[1].length == 1) ? (opt[k]) : (opt[k].padStart(ret[1].length, "0")))
                    };
                };
                return fmt;
            }
            function random(min, max) {
                return Math.floor(Math.random() * (max - min)) + min;
            }
            return dateFormat("YYYY_mm_dd_HH_MM_SS", new Date()) + "_" + random(1, 100);
        }
        Java.perform(function () {
            function storeP12(privateKey, certificate, saveP12Path, p12Password) {
                var X509Certificate = Java.use("java.security.cert.X509Certificate")
                var p7X509 = Java.cast(certificate, X509Certificate);
                var chain = Java.array("java.security.cert.X509Certificate", [p7X509])
                var ks = Java.use("java.security.KeyStore").getInstance("PKCS12", "BC");
                ks.load(null, null);
                ks.setKeyEntry("client", privateKey, Java.use('java.lang.String').$new(p12Password).toCharArray(), chain);
                try {
                    var out = Java.use("java.io.FileOutputStream").$new(saveP12Path);
                    ks.store(out, Java.use('java.lang.String').$new(p12Password).toCharArray())
                } catch (exp) {
                    console.log(exp)
                }
            }
            Java.use("java.security.KeyStore$PrivateKeyEntry").getPrivateKey.implementation = function () {
                var packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
                var savePath = '/sdcard/Download/' + packageName;

                var result = this.getPrivateKey();
                var fileName = savePath + getNowTime() + '.p12'
                storeP12(this.getPrivateKey(), this.getCertificate(), fileName, password);
                console.log("dump ClinetCertificate=>", fileName, "pwd:" + password);
                return result;
            }
            Java.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function () {
                var packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
                var savePath = '/sdcard/Download/' + packageName;
                var result = this.getCertificateChain()
                var fileName = savePath + getNowTime() + '.p12'
                storeP12(this.getPrivateKey(), this.getCertificate(), fileName, password);
                console.log("dump ClinetCertificate=>", fileName, "pwd:" + password);
                return result;
            }
        });
    },

    /**
     * 对toast进行hook
     */
    hook_toast: function hook_toast() {
        let thiz = this;
        Java.perform(function () {
            var Toast = Java.use("android.widget.Toast");
            Toast.show.implementation = function () {
                thiz.printStack("SHOW Toast");
                return this.show();
            };
        });
    }

}

setImmediate(main)