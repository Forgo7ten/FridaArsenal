function findImpByInterface(packageName,interfaceName){
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
                        for(var i in interfaces){
                            if(interfaces[i].toString().indexOf(interfaceName)>=0){
                                console.log(class_name,":",interfaces[i].toString())
                            }
                        }
                    }
                }
            },
            onComplete:function(){
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