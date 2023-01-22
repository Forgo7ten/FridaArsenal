/**
 * 通过提供的父类名称，在限定范围内查找子类
 * @param {String} whiteClsName 白名单筛选
 * @param {String} superClassName 要寻找子类的父类名称
 * @param {String} blackClsName 黑名单
 */
function findChildBySuper(whiteClsName,superClassName, blackClsName = "") {
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
                    while(superClass!=null){
                        if(superClass.toString().indexOf(superClassName)>=0){
                            console.log("Found:",class_name,superClass);
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