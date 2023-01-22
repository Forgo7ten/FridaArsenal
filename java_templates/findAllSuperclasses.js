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
