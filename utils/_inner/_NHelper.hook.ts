import {Flog} from "../Flog";
import {soHookerHandler} from "../native/SoHookerHandler";

export const _NHelperHook = (() => {

    /**
     * 在so初始化之前hook（只能hook一个so）
     * @param soname 要hook的so的名称，如libxxx.so
     * @param callback 自定义需要执行的回调函数
     */
    function hookBeforeSoInit(soname: string, callback: (soModule: Module) => void): void {
        let hooked = false;
        let linker_m: Module;
        if (Process.pointerSize == 4) {
            linker_m = Process.findModuleByName("linker");
        } else if (Process.pointerSize == 8) {
            linker_m = Process.findModuleByName("linker64");
        } else {
            Flog.e(`Not found linker.`)
        }
        let call_constructors_addr = null;
        let symbols = linker_m.enumerateSymbols();
        for (let i = 0; i < symbols.length; i++) {
            let sym_name = symbols[i].name;
            if (sym_name.includes(`soinfo`) && sym_name.includes(`call_constructors`)) {
                call_constructors_addr = symbols[i].address;
                break;
            }
        }
        Interceptor.attach(call_constructors_addr, {
            onEnter: function (args) {
                // Flog.d(_NHookHelper.TAG, `Called call_constructors`)
                let so = Process.findModuleByName(soname)
                if (so && !hooked) {
                    callback(so);
                    hooked = true;
                }
            }
        })
    }

    /**
     * 在so加载完成之后hook（只能hook一个so）
     * @param soname 要hook的so的名称，如libxxx.so
     * @param callback 自定义需要执行的回调函数
     */
    function hookAfterSoLoad(soname: string, callback: (soModule: Module) => void) {
        /*
        // 注释掉，防止执行多次
        let dlopen_np = Module.findExportByName("libdl.so", "dlopen");
        if (dlopen_np) {
            Interceptor.attach(dlopen_np, {
                onEnter: function (args) {
                    let filename = args[0].readCString();
                    let flag = args[1];
                    if (filename.includes(soname)) {
                        // Flog.d(`dlopen called for ${filename}`);
                        this.shouldCallback = true;
                    }
                }, onLeave: function (retval) {
                    if (this.shouldCallback) {
                        let so = Process.findModuleByName(soname)
                        if (so) {
                            callback(so);
                        }
                    }
                }
            })
            Flog.d("attach libdl.so -> dlopen(const char* filename, int flag)")
        }*/
        let android_dlopen_ext_np = Module.findExportByName("libdl.so", "android_dlopen_ext");
        if (android_dlopen_ext_np) {
            Interceptor.attach(android_dlopen_ext_np, {
                onEnter: function (args) {
                    let filename = args[0].readCString();
                    if (filename.includes(soname)) {
                        // Flog.d(`android_dlopen_ext called for ${filename}`);
                        this.shouldCallback = true;
                    }
                }, onLeave: function (retval) {
                    if (this.shouldCallback) {
                        let so = Process.findModuleByName(soname)
                        if (so) {
                            callback(so);
                        }
                    }
                }
            })
            Flog.d("attach libdl.so -> android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo)")
        }
    }


    function addHookerA(soname: string, callback: (soModule: Module) => void) {
        return soHookerHandler.addHookerAfterSoLoad(soname, callback);
    }

    function addHookerAfterSoLoad(soname: string, callback: (soModule: Module) => void) {
        return soHookerHandler.addHookerAfterSoLoad(soname, callback);
    }

    function addHookerB(soname: string, callback: (soModule: Module) => void) {
        return soHookerHandler.addHookerBeforeSoInit(soname, callback);
    }

    function addHookerBeforeSoInit(soname: string, callback: (soModule: Module) => void) {
        return soHookerHandler.addHookerBeforeSoInit(soname, callback);
    }

    return {
        hookBeforeSoInit,
        hookAfterSoLoad,
        soHookerHandler,
        addHookerA,
        addHookerAfterSoLoad,
        addHookerB,
        addHookerBeforeSoInit,
    }
})()