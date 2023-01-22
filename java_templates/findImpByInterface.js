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

function main() {
    var packageName = "com.forgotten.fridatestapp";
    var interfaceName = "android.view.View$OnClickListener";
    findInterface(packageName, interfaceName);
}