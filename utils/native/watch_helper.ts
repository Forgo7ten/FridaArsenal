import {common} from "../common";
import {_NHelper} from "./helper";
import Flog = common.Flog;

export class _NWatchHelper {

    /**
     * 监控so的加载
     * @param printBacktrace 是否打印栈回溯
     */
    static watchSoLoad(printBacktrace: boolean = false) {
        let dlopen_np = Module.findExportByName("libdl.so", "dlopen");
        let android_dlopen_ext_np = Module.findExportByName("libdl.so", "android_dlopen_ext");
        if (dlopen_np) {
            Interceptor.attach(dlopen_np, {
                onEnter: function (args) {
                    let filename = args[0].readCString();
                    let flag = args[1];
                    Flog.i(`Loading ${filename} ;flag=${flag}`)
                    if (printBacktrace) {
                        _NHelper.printBacktrace(`dlopen(${filename})`, this.context)
                    }
                }
            })
            Flog.d("attach libdl.so -> dlopen(const char* filename, int flag)")
        }
        if (android_dlopen_ext_np) {
            Interceptor.attach(android_dlopen_ext_np, {
                onEnter: function (args) {
                    let filename = args[0].readCString();
                    let flag = args[1];
                    let extinfo = args[2];
                    Flog.i(`Loading ${filename} ;flag=${flag}`)
                    if (printBacktrace) {
                        _NHelper.printBacktrace(`android_dlopen_ext(${filename})`, this.context)
                    }
                }
            })
            Flog.d("attach libdl.so -> android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo)")
        }
    }

    /**
     * 来自 https://github.com/lasting-yang/frida_hook_libart
     */
    static find_RegisterNatives() {
        function hook_RegisterNatives(addrRegisterNatives) {
            if (addrRegisterNatives != null) {
                Interceptor.attach(addrRegisterNatives, {
                    onEnter: function (args) {
                        console.log("[RegisterNatives] method_count:", args[3]);
                        var env = args[0];
                        var java_class = args[1];
                        var class_name = Java.vm.tryGetEnv().getClassName(java_class);
                        //console.log(class_name);

                        // @ts-ignore
                        var methods_ptr = ptr(args[2]);

                        // @ts-ignore
                        var method_count = parseInt(args[3]);
                        for (var i = 0; i < method_count; i++) {
                            // @ts-ignore
                            var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
                            // @ts-ignore
                            var sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
                            // @ts-ignore
                            var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));

                            // @ts-ignore
                            var name = Memory.readCString(name_ptr);
                            // @ts-ignore
                            var sig = Memory.readCString(sig_ptr);
                            var find_module = Process.findModuleByAddress(fnPtr_ptr);
                            console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr, " fnOffset:", ptr(fnPtr_ptr).sub(find_module.base), " callee:", DebugSymbol.fromAddress(this.returnAddress));

                        }
                    }
                });
            }
        }

        // @ts-ignore
        var symbols = Module.enumerateSymbolsSync("libart.so");
        var addrRegisterNatives = null;
        for (var i = 0; i < symbols.length; i++) {
            var symbol = symbols[i];

            //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
            if (symbol.name.indexOf("art") >= 0 &&
                symbol.name.indexOf("JNI") >= 0 &&
                symbol.name.indexOf("RegisterNatives") >= 0 &&
                symbol.name.indexOf("CheckJNI") < 0) {
                addrRegisterNatives = symbol.address;
                console.log("RegisterNatives is at ", symbol.address, symbol.name);
                hook_RegisterNatives(addrRegisterNatives)
            }
        }

    }

}
