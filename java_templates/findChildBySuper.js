function findChildBySuper(packageName,superClassName) {
    Java.perform(function () {
        Java.enumerateLoadedClasses({
            onMatch: function (class_name) {
                if(class_name.indexOf("DynamicDex")>=0){
                    return;
                }
                // 对搜索范围进行限定
                if (class_name.indexOf(packageName) < 0) {
                    return;
                } else {
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