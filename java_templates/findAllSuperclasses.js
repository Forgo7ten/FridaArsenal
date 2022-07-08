function findAllSuperclasses(packageName){
    Java.perform(function(){
        Java.enumerateLoadedClasses({
            onMatch:function(class_name){
                //
                if(class_name.indexOf("fridatestapp.DynamicDex")>=0){
                    return;
                }
                //
                if(class_name.indexOf(packageName)<0){
                    return;
                }else{
                    var hook_cls = Java.use(class_name);
                    var superClass = hook_cls.class.getSuperclass();
                    console.log(class_name,":")
                    while(superClass!=null){
                        console.log("\t",superClass.toString());
                        superClass = superClass.getSuperclass();
                    }
                }
            },
            onComplete:function(){
                console.log("findAllSuperclasses end");
            }
        })
    })
}
