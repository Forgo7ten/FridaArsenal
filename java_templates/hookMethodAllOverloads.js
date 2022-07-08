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

function main() {
    var className = "com.forgotten.fridatestapp.HookedObject";
    var methodName = "addNumber";
    hookMethodAllOverloads(className, methodName);
}