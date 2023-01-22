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

