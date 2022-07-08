function main1() {
    /* 主动调用 可导出的native函数 */
    Java.perform(function invoke_justAdd_func() {
        // 寻找模块so的地址
        var lib_fridatestapp_addr = Module.findBaseAddress("libfridatestapp.so");
        console.log("native_lib_addr -> ", lib_fridatestapp_addr);
        // 寻找导出函数的地址
        var justAdd_addr = Module.findExportByName("libfridatestapp.so", "_Z7justAddii");
        console.log("justAdd() addr -> ", justAdd_addr);
        // 新建一个Native函数，参数分别为 已存在函数地址，函数返回值类型，函数参数列表
        var justAdd_func = new NativeFunction(justAdd_addr, "int", ["int", "int"]);
        // 执行函数，获得函数返回值
        var justAdd_result = justAdd_func(10, 2);
        console.log("invoke justAdd(10,2) result-> ", justAdd_result);
    });

    Java.perform(function invoke_nativeString_func() {
        /* 大部分代码同 hook函数中的 */
        // 寻找模块so的地址
        var lib_fridatestapp_addr = Module.findBaseAddress("libfridatestapp.so");
        console.log("native_lib_addr -> ", lib_fridatestapp_addr);
        // 寻找导出函数的地址
        var staticString_addr = Module.findExportByName("libfridatestapp.so", "Java_com_forgotten_fridatestapp_MainActivity_staticString");
        console.log("staticString() addr -> ", staticString_addr);

        /* 声明该native函数，返回值和参数env、jobject等都是"pointer" */
        var nativeString_func = new NativeFunction(staticString_addr, "pointer", ["pointer", "pointer", "pointer"]);

        // 对函数进行attach
        Interceptor.attach(staticString_addr, {
            // 函数进入时，参数为函数的参数
            onEnter: function (args) {
                // 打印三个参数地址
                console.log("Interceptor.attach staticString() args:", args[0], args[1], args[2]);
                // 将 参数三传进去的jstring字符串，转换为char*再用readCString()得到JavaScript字符串来输出
                console.log("jstring is", Java.vm.getEnv().getStringUtfChars(args[2], null).readCString());

                /* 主动调用方法，打印函数结果 */
                console.log("==> invoke stringfunc(): ", Java.vm.getEnv().getStringUtfChars(nativeString_func(args[0], args[1], args[2]), null).readCString());

                // 可以对参数进行修改
                var new_arg2 = Java.vm.getEnv().newStringUtf("new arg2 from Frida");
                args[2] = new_arg2;
            },
            // 函数执行完的时候，参数为函数的返回值
            onLeave: function (reval) {
                console.log("Interceptor.attach staticString() retval", reval);
                console.log("Interceptor.attach staticString() retval", Java.vm.getEnv().getStringUtfChars(reval, null).readCString());

                // 对函数的返回值进行替换
                var new_reval = Java.vm.getEnv().newStringUtf("HaHa Frida!!!");
                reval.replace(new_reval);
            },
        });
    });
}