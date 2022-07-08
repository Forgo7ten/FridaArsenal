const len = Java.vm.getEnv().getArrayLength(jstringArr);
console.log("len", len);
for(var i=0;i<len;i++){
     var obj = Java.vm.getEnv().getObjectArrayElement (jstringArr,i);
     // console.log(obj);
     // 方式一：
     // var element = Java.cast(obj, Java.use("java.lang.String"));
     // 方式二：
     var element = Java.vm.getEnv().getStringUtfChars(obj, null).readCString();
     console.log("第"+i+"个:"+ element)
 }