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