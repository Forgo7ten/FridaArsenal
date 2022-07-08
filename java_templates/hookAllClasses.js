function main(){
    Java.perform(function(){
        Java.enumerateLoadedClasses({
            // name为加载的类名字符串
            onMatch: function(name,handle){
                // 可以通过包名限定需要处理的类名
                if (name.indexOf("com.forgotten.fridatestapp") != -1){
                    console.log(name,handle);
                    // 利用反射 获取类中的所有方法
                    var TargetClass = Java.use(name);
                    // return Method Object List
                    var methodsList = TargetClass.class.getDeclaredMethods(); 
                    for (var i = 0; i < methodsList.length; i++){
                        // 打印其中方法的名字
                        console.log(methodsList[i].getName());
                        // 可以hook该类中的所有方法
                        hookMethodAllOverloads(name,methodsList[i].getName());
                    }
                }
            },
            
            onComplete: function(){
                console.log("enumerateLoadedClasses complete!!!")
            }
        })
    })
}