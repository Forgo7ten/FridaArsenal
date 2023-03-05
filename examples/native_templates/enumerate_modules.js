/**
 * 遍历导出表与符号表 Example
 */

/**
 * 写文件
 * @param {*} path 写文件的路径
 * @param {*} contents 写文件的内容
 */
function writeSomething(path, contents) {
    var fopen_addr = Module.findExportByName("libc.so", "fopen");
    var fputs_addr = Module.findExportByName("libc.so", "fputs");
    var fclose_addr = Module.findExportByName("libc.so", "fclose");

    //console.log("fopen=>",fopen_addr,"  fputs=>",fputs_addr,"  fclose=>",fclose_addr);

    var fopen = new NativeFunction(fopen_addr, "pointer", ["pointer", "pointer"]);
    var fputs = new NativeFunction(fputs_addr, "int", ["pointer", "pointer"]);
    var fclose = new NativeFunction(fclose_addr, "int", ["pointer"]);

    //console.log(path,contents)

    var fileName = Memory.allocUtf8String(path);
    var mode = Memory.allocUtf8String("a+");

    var fp = fopen(fileName, mode);

    var contentHello = Memory.allocUtf8String(contents);
    var ret = fputs(contentHello, fp);

    fclose(fp);
}

/** 对指定函数进行attachHOOK **/
function attach(name, address) {
    console.log("attaching ", name);
    Interceptor.attach(address, {
        onEnter: function (args) {
            console.log("Entering => ", name);
        },
        onLeave: function (retval) {
            //console.log("retval is => ",retval)
        },
    });
}

var app_packagename = "com.forgotten.learntest";

/* 遍历moudles的exports */
function traceNativeExport() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var module = modules[i];

        if (module.name.indexOf("libssl.so") < 0) {
            continue;
        }
        var path = "/data/data/" + app_packagename + "/cache/" + module.name + "_exports.txt";
        var exports = module.enumerateExports();
        for (var j = 0; j < exports.length; j++) {
            console.log("module name is =>", module.name, " symbol name is =>", exports[j].name);

            writeSomething(path, "type: " + exports[j].type + " function name :" + exports[j].name + " address : " + exports[j].address + " offset => 0x" + exports[j].address.sub(modules[i].base) + "\n");
            if (exports[j].name.indexOf("SSL_write") >= 0) {
                attach(exports[j].name, exports[j].address);
            }
        }
    }
}

/* 遍历moudles的symbols */
function traceNativeSymbol() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var module = modules[i];
        // console.log(JSON.stringify(module));
        /*可以对指定module进行过滤*/

        if (module.name.indexOf("linker64") < 0) {
            continue;
        }
        var path = "/data/data/" + app_packagename + "/cache/" + module.name + "_symbols.txt";
        var exports = module.enumerateSymbols();
        // console.log(JSON.stringify(exports))
        for (var j = 0; j < exports.length; j++) {
            if (exports[j] == null) {
                continue;
            }
            console.log("module name is =>", module.name, " symbol name is =>", exports[j].name);

            writeSomething(path, "type: " + exports[j].type + " function name :" + exports[j].name + " address : " + exports[j].address + " offset => 0x" + exports[j].address.sub(modules[i].base) + "\n");
        }
    }
}

function main() {
    console.log("Entering main");
    traceNativeExport();
    traceNativeSymbol();
}
setImmediate(main);
