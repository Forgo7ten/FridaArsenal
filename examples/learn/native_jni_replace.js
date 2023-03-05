/* 对NewStringUTF函数进行replace操作 */
function replace_NewStringUTF_func() {
    /* 同上 */
    var NewStringUTF_addr = null;
    // 该函数在这个so里面，遍历里面的所有符号
    var symbools = Process.findModuleByName("libart.so").enumerateSymbols();
    //console.log(JSON.stringify(symbool));
    for (var i = 0; i < symbools.length; i++) {
        // 取到符号的name
        var symbol = symbools[i].name;
        // 过滤一下，因为还有一个checkjni类中有该函数
        if (symbol.indexOf("CheckJNI") == -1 && symbol.indexOf("JNI") >= 0) {
            if (symbol.indexOf("NewStringUTF") >= 0) {
                console.log("finally found NewStringUTF_name:", symbol);
                // 保存该函数的地址
                NewStringUTF_addr = symbools[i].address;
                console.log("finally found NewStringUTF_address :", NewStringUTF_addr);
            }
        }
    }

    // new一个NewStringUTF的NativeFunction
    /* static jstring NewStringUTF(JNIEnv* env, const char* utf) */
    var NewStringUTF = new NativeFunction(NewStringUTF_addr, "pointer", ["pointer", "pointer"]);
    // 然后执行替换
    Interceptor.replace(
        NewStringUTF_addr,
        new NativeCallback(
            function (arg1, arg2) {
                // 打印原本的参数
                console.log("NewStringUTF arg1,arg2->", arg1, arg2.readCString());
                // new一个char*字符串
                var newARG2 = Memory.allocUtf8String("newPARG2");
                /* 将参数替换，然后执行原函数并返回结果
        var result=NewStringUTF(arg1,newARG2); // 不能随意修改，会导致崩溃*/
                var result = NewStringUTF(arg1, arg2);
                return result;
            },
            "pointer",
            ["pointer", "pointer"]
        )
    );
}