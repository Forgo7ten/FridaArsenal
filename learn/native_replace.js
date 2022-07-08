function main2() {
    /* 替换 justAdd函数 */
    Java.perform(function replace_func() {
        // 寻找模块so的地址
        var lib_fridatestapp_addr = Module.findBaseAddress("libfridatestapp.so");
        console.log("native_lib_addr -> ", lib_fridatestapp_addr);
        // 寻找导出函数的地址
        var justAdd_addr = Module.findExportByName("libfridatestapp.so", "_Z7justAddii");
        console.log("justAdd() addr -> ", justAdd_addr);
        // 对原native函数进行替换，参数1为替换的地址，参数2为一个NativeCallback
        Interceptor.replace(
            justAdd_addr,
            new NativeCallback(
                // 参数分别为，替换执行的函数，返回值类型，参数类型列表
                function (a, b) {
                    console.log("justAdd args: ", a, b);
                    var result = a * (b + 5);
                    console.log("new Func Result: ", result);
                    return result;
                },
                "int",
                ["int", "int"]
            )
        );
    });
}