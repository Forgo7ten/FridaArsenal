function main1(){
    Java.perform(()=>{
        // hello
    })
    console.warn("Done!")
}


function main(){
    // 添加逻辑
    main1();
}















































/********************========== 分割线 ==========********************/


/**
 * 寻找指定类的所有接口并打印
 * @param {String} whiteClsName 要寻找接口的类名称
 * @param {String} blackClsName 黑名单
 */
function findAllInterfaces(whiteClsName, blackClsName = "") {
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
}

/**
 * 寻找指定类的所有父类并打印
 * @param {String} whiteClsName 要寻找父类的类名称
 * @param {String} blackClsName 黑名单
 */
function findAllSuperclasses(whiteClsName, blackClsName = "") {
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
}

/**
 * 通过提供的父类名称，在限定范围内查找子类
 * @param {String} whiteClsName 白名单筛选
 * @param {String} superClassName 要寻找子类的父类名称
 * @param {String} blackClsName 黑名单
 */
function findChildBySuper(whiteClsName, superClassName, blackClsName = "") {
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
}

/**
 * 通过hook的方式来获取classloader，并设置
 */
function getClassLoaderByHook() {
    let ActivityThread_clazz = Java.use("android.app.ActivityThread");
    ActivityThread_clazz["performLaunchActivity"].implementation = function () {
        let ret = this["performLaunchActivity"].apply(this, arguments);
        Java.classFactory.loader = this.mInitialApplication.value.getClassLoader();
        return ret;
    }
}

/**
 * 同步的方式来寻找classloader
 * @param {String} className 尝试加载的类
 */
function findClassLoaderSync(className) {
    Java.perform(() => {
        let clsLoaders = Java.enumerateClassLoadersSync();
        for (let loader of clsLoaders) {
            try {
                // 如果找到的类加载器 能加载的类有[className]
                if (loader.findClass(className)) {
                    console.log("Successfully found loader");
                    // 设置 java默认的classloader
                    Java.classFactory.loader = loader;
                }
            } catch (error) {
                // console.log("error:" + error);
            }
        }
        func()
    })
}


/**
 * 异步的方式来寻找classloader，之后调用回调函数
 * @param {String} className 尝试加载的类
 * @param {*} callback 回调函数
 */
function findClassLoader(className, callback = () => { }) {
    Java.perform(function () {
        // 枚举内存中的 类加载器
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    // 如果找到的类加载器 能加载的类有[class_name]
                    if (loader.findClass(className)) {
                        console.log("Successfully found loader");
                        console.log(loader);
                        // 设置 java默认的classloader
                        Java.classFactory.loader = loader;
                    }
                } catch (error) {
                    console.log("find error:" + error);
                }
            },
            onComplete: function () {
                console.log("End");
            },
        });
        // 再 使用该类
        callback();
    });
}

/**
 * 通过提供的接口名称，在限定范围内查找实现类
 * @param {String} whiteClsName 白名单筛选
 * @param {String} interfaceName 要寻找实现类的接口名称
 * @param {String} blackClsName 黑名单
 */
function findImpByInterface(whiteClsName, interfaceName, blackClsName = "") {
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
}

function getContext() {
    Java.perform(function () {
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
        var context = currentApplication.getApplicationContext();
        console.log(context);
        return context;
        /* var packageName = context.getPackageName();
        console.log(packageName);
        console.log(currentApplication.getPackageName()); */
    })
}

/**
 * 对某些类或包的所有方法进行hook
 * @param {String} whiteClsName 白名单
 * @param {String} blackClsName 黑名单，禁止出现的字符串
 */
function hookSomeClasses(whiteClsName, blackClsName = "") {
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
                        hookMethodAllOverloads(name, methodsList[i].getName());
                    }
                }
            },
            onComplete: function () {
                console.log("enumerateLoadedClasses complete!!!")
            }
        })
    })
}

/**
 * hook方法的每一个重载
 * @param {String} className 要hook的类名
 * @param {String} methodName 要hook的方法名
 */
function hookMethodAllOverloads(className, methodName) {
    Java.perform(function () {
        // hook 指定方法的所有重载
        var clazz = Java.use(className);
        // Object.toString同Object["toString"]
        var overloadsLength = clazz[methodName].overloads.length;
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
}

function printStack(name = "") {
    Java.perform(function () {
        var throwable = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        console.log("=============================" + name + " Stack strat=======================");
        console.log(throwable);
        console.log("=============================" + name + " Stack end=======================\r\n");
    });
}

function printStack1(name = "") {
    Java.perform(function () {
        var exception = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        console.log("=============================" + name + " Stack strat=======================");
        console.log(exception);
        console.log("=============================" + name + " Stack end=======================\r\n");
    });
}

function printStack2(name = "") {
    Java.perform(function () {
        var Exception = Java.use("java.lang.Exception");
        var ins = Exception.$new("Exception");
        var straces = ins.getStackTrace();
        if (straces != undefined && straces != null) {
            var strace = straces.toString();
            var replaceStr = strace.replace(/,/g, "\n");
            console.log("=============================" + name + " Stack strat=======================");
            console.log(replaceStr);
            console.log("=============================" + name + " Stack end=======================\r\n");
            Exception.$dispose();
        }
    });
}



gson_init_flag = false;
/**
 * 将对象转成json
 * @param {object} obj 要转成json的对象
 * @returns json字符串
 */
function toGson(obj) {
    if (!gson_init_flag) {
        Java.openClassFile("/data/local/tmp/r0gson.dex").load();
        gson_init_flag = true;
    }
    const gson = Java.use('com.r0ysue.gson.Gson');
    return gson.$new().toJson(obj);
}


/**
 * 对toast进行hook
 */
function hook_toast() {
    Java.perform(function () {
        var Toast = Java.use("android.widget.Toast");
        Toast.show.implementation = function () {
            printStack("SHOW Toast");
            return this.show();
        };
    });
}


setImmediate(main)