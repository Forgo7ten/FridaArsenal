/* 枚举出所有模块的所有导出符号 */
function EnumerateAllExports() {
    var modules = Process.enumerateModules();
    //print all modules
    //console.log("Process.enumerateModules->",JSON.stringify(modules));
    for (var i = 0; i < modules.length; i++) {
        var module = modules[i];
        var module_name = modules[i].name;
        var exports = module.enumerateExports();
        console.log("module.enumerateeExports", JSON.stringify(exports));
    }
}