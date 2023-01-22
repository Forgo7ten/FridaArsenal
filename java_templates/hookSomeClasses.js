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