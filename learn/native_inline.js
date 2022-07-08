function main3() {
    /* 靠地址偏移hook未导出函数  */
    Java.perform(function () {
        // 寻找模块so的地址
        var lib_fridatestapp_addr = Module.findBaseAddress("libfridatestapp.so");
        console.log("native_lib_addr -> ", lib_fridatestapp_addr);
        // 通过函数偏移+模块的地址，得到函数的地址
        var dynamicString_addr = lib_fridatestapp_addr.add(0xa48);
        console.log("dynamicString() addr -> ", dynamicString_addr);
        // 对函数进行attach
        Interceptor.attach(dynamicString_addr, {
            // 函数进入时，参数为函数的参数
            onEnter: function (args) {
                /* 打印native函数调用栈，有Backtracer.ACCURATE和Backtracer.FUZZY两种模式切换 */
                // console.log("CCCryptorCreate called from:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") + "\n");

                // 打印三个参数地址
                console.log("Interceptor.attach dynamicString() args:", args[0], args[1], args[2]);
                // 将 参数三传进去的jstring字符串，转换为char*再用readCString()得到JavaScript字符串来输出
                // console.log("jstring is", Java.vm.getEnv().getStringUtfChars(args[2], null).readCString());

                // 可以对参数进行修改
                var new_arg2 = Java.vm.getEnv().newStringUtf("new arg2 from Frida");
                args[2] = new_arg2;
            },
            // 函数执行完的时候，参数为函数的返回值
            onLeave: function (reval) {
                console.log("Interceptor.attach dynamicString() retval", reval);
                console.log("Interceptor.attach dynamicString() retval", Java.vm.getEnv().getStringUtfChars(reval, null).readCString());

                // 对函数的返回值进行替换
                var new_reval = Java.vm.getEnv().newStringUtf("HaHa Frida!!!");
                // reval.replace(new_reval);
            },
        });
    });
}