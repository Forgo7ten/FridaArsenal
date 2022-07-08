/* hook jni函数GetStringUTFChars */
function hook_getStringUTFChars_func() {
    var GetStringUTFChars_addr = null;
    // 该函数在这个so里面，遍历里面的所有符号
    var symbools = Process.findModuleByName("libart.so").enumerateSymbols();
    //console.log(JSON.stringify(symbool));
    for (var i = 0; i < symbools.length; i++) {
        // 取到符号的name
        var symbol = symbools[i].name;
        // 过滤一下，因为还有一个checkjni类中有该函数
        if (symbol.indexOf("CheckJNI") == -1 && symbol.indexOf("JNI") >= 0) {
            if (symbol.indexOf("GetStringUTFChars") >= 0) {
                console.log("finally found GetStringUTFChars name:", symbol);
                // 保存该函数的地址
                GetStringUTFChars_addr = symbools[i].address;
                console.log("finally found GetStringUTFChars address :", GetStringUTFChars_addr);
            }
        }
    }
    /* 开始附加该函数 */
    Interceptor.attach(GetStringUTFChars_addr, {
        onEnter: function (args) {
            console.log("art::JNI::GetStringUTFChars(_JNIEnv*,_jstring*,unsigned char*)->", args[0], Java.vm.getEnv().getStringUtfChars(args[1], null).readCString(), args[2]);
            // 打印栈回溯
            // console.log("CCCryptoCreate called from:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") + "\n");
        },
        onLeave: function (retval) {
            // 打印返回值，为c字符串
            console.log("retval is->", retval.readCString());
        },
    });
}