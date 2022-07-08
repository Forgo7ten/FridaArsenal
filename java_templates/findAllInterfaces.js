function findAllInterfaces(packageName){
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
                    var clazz = Java.use(class_name);
                    var interfaces = clazz.class.getInterfaces();
                    if(interfaces.length>0){
                        console.log(class_name,":");
                        for(var i in interfaces){
                            console.log("\t",interfaces[i].toString())
                        }
                    }
                }
            },
            onComplete:function(){
                console.log("findAllInterfaces end");
            }
        })
    })
}

function main() {
    var packageName = "com.forgotten.fridatestapp";
    findAllInterfaces(packageName);
}
