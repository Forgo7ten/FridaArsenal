import {Flog} from "../Flog";
import {_NHelperCore} from "./_NHelper.core";
import {soHookerHandler} from "../native/SoHookerHandler";

const {printBacktrace} = _NHelperCore
export const _NHelperWatch = (() => {


    /**
     * 监控so的加载
     * @param printBacktraceFlag 是否打印栈回溯
     */
    function watch_so_load(printBacktraceFlag: boolean = false) {
        let dlopen_np = Module.findExportByName("libdl.so", "dlopen");
        let android_dlopen_ext_np = Module.findExportByName("libdl.so", "android_dlopen_ext");
        if (dlopen_np) {
            Interceptor.attach(dlopen_np, {
                onEnter: function (args) {
                    let filename = args[0].readCString();
                    let flag = args[1];
                    Flog.i(`Loading ${filename} ;flag=${flag}`)
                    if (printBacktraceFlag) {
                        printBacktrace(`dlopen(${filename})`, this.context)
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
                    if (printBacktraceFlag) {
                        printBacktrace(`android_dlopen_ext(${filename})`, this.context)
                    }
                }
            })
            Flog.d("attach libdl.so -> android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo)")
        }
    }


    /**
     * 监控pthread_create函数
     * @param soname 要hook的so的名称，会在加载时机hook；为null则自己选择时机hook
     * @param cbFunc 回调函数，接收原始pthread_create函数、及参数；可以自己处理逻辑
     */
    function watch_pthread_create(soname: string = null, cbFunc: (origFunc: NativeFunction<number, [NativePointer, NativePointer, NativePointer, NativePointer]>, cbCtx: CallbackContext, thread, attr, start_routine: NativePointer, arg) => number = null) {
        let pthread_create_addr = Module.findExportByName("libc.so", "pthread_create");
        if (pthread_create_addr) {
            let orig_pthread_create = new NativeFunction(pthread_create_addr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
            const performHook = () => {
                Interceptor.replace(pthread_create_addr, new NativeCallback(function (thread, attr, start_routine, arg) {
                    Flog.i(`[pthread_create] thread=${thread}, attr=${attr}, start_routine=${start_routine}, arg=${arg}`);
                    let result;
                    let func_module = Process.findModuleByAddress(start_routine)
                    if (func_module) {
                        Flog.i(`[pthread_create] ${start_routine}(${start_routine.sub(func_module.base)}) in ${func_module.name} `);
                    } else {
                        Flog.i(`[pthread_create] ${start_routine}`);
                    }
                    if (cbFunc) {
                        result = cbFunc(orig_pthread_create, this, thread, attr, start_routine, arg);
                    } else {
                        result = orig_pthread_create(thread, attr, start_routine, arg);
                        Flog.i(`[pthread_create] returned: ${result}`);
                    }
                    return result;
                }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
            };
            soname
                ? soHookerHandler.addHooker(soname, performHook)
                : performHook();
        } else {
            Flog.e("Unable to find pthread_create function address.");
        }
    }

    /**
     * 监控access函数
     * @param cbFunc
     * @param printBacktraceFlag
     */
    function watch_access(cbFunc: (origFunc: NativeFunction<number, [NativePointer, number]>, cbCtx: CallbackContext, pathname: NativePointer, mode: number) => number = null, printBacktraceFlag: boolean = false) {
        const access_addr = Module.findExportByName("libc.so", "access");
        if (access_addr) {
            let orig_access = new NativeFunction(access_addr, 'int', ['pointer', 'int']);
            Interceptor.replace(access_addr, new NativeCallback(function (pathname, mode) {
                let result;
                let path = pathname.readCString();
                if (printBacktraceFlag) {
                    printBacktrace(`[access] ${path}  with mode ${mode}`, this.context);
                } else {
                    Flog.i(`[access] ${path}  mode ${mode}`);
                }
                if (cbFunc) {
                    result = cbFunc(orig_access, this, pathname, mode);
                } else {
                    result = orig_access(pathname, mode);
                    Flog.i(`[access] Result: ` + result);
                }
                return result;
            }, 'int', ['pointer', 'int']));
        } else {
            Flog.e("Unable to find [access] function address.");
        }
    }

    /**
     * 监控open函数
     * @param cbFunc
     * @param printBacktraceFlag
     */
    function watch_open(cbFunc: (origFunc: NativeFunction<number, [NativePointer, number]>, cbCtx: CallbackContext, pathname: NativePointer, flags: number) => number = null, printBacktraceFlag: boolean = false) {
        const open_addr = Module.findExportByName("libc.so", "open");
        if (open_addr) {
            let orig_open = new NativeFunction(open_addr, 'int', ['pointer', 'int']);
            Interceptor.replace(open_addr, new NativeCallback(function (pathname, flags) {
                let result;
                let path = pathname.readCString();
                if (printBacktraceFlag) {
                    printBacktrace(`[open] ${path} with flags ${flags}`, this.context);
                } else {
                    Flog.i(`[open] ${path} with flags ${flags}`);
                }
                if (cbFunc) {
                    result = cbFunc(orig_open, this, pathname, flags);
                } else {
                    result = orig_open(pathname, flags);
                    Flog.i(`[open] Result: ` + result);
                }
                return result;
            }, 'int', ['pointer', 'int']));
        } else {
            Flog.e("Unable to find [open] function address.");
        }
    }


    /**
     * 监控openat函数 (no test)
     * @param cbFunc
     * @param printBacktraceFlag
     */
    function watch_openat(cbFunc: (origFunc: NativeFunction<number, [number, NativePointer, number]>, cbCtx: CallbackContext, dirfd: number, pathname: NativePointer, mode: number) => number = null, printBacktraceFlag: boolean = false) {
        const openat_addr = Module.findExportByName("libc.so", "openat");
        if (openat_addr) {
            let orig_openat = new NativeFunction(openat_addr, 'int', ['int', 'pointer', 'int']);
            Interceptor.replace(openat_addr, new NativeCallback(function (dirfd, pathname, mode) {
                let result;
                let path = pathname.readCString();
                if (printBacktraceFlag) {
                    printBacktrace(`[openat] ${path} with mode ${mode}`, this.context);
                } else {
                    Flog.i(`[openat] ${path} with mode ${mode}`);
                }
                if (cbFunc) {
                    result = cbFunc(orig_openat, this, dirfd, pathname, mode);
                } else {
                    result = orig_openat(dirfd, pathname, mode);
                    Flog.i(`[openat] Result: ` + result);
                }
                return result;
            }, 'int', ['int', 'pointer', 'int']));
        } else {
            Flog.e("Unable to find [openat] function address.");
        }
    }

    /**
     * 监控fopen函数（会调用open函数）
     * @param cbFunc
     * @param printBacktraceFlag
     */
    function watch_fopen(cbFunc: (origFunc: NativeFunction<NativePointer, [NativePointer, NativePointer]>, cbCtx: CallbackContext, filename: NativePointer, mode: NativePointer) => NativePointer = null, printBacktraceFlag: boolean = false) {
        const fopen_addr = Module.findExportByName("libc.so", "fopen");
        if (fopen_addr) {
            let orig_fopen = new NativeFunction(fopen_addr, 'pointer', ['pointer', 'pointer']);
            Interceptor.replace(fopen_addr, new NativeCallback(function (filename, mode) {
                let result;
                let filePath = filename.readCString();
                if (printBacktraceFlag) {
                    printBacktrace(`[fopen] ${filePath} with mode ${mode.readCString()}`, this.context);
                } else {
                    Flog.i(`[fopen] ${filePath} with mode ${mode.readCString()}`);
                }
                if (cbFunc) {
                    result = cbFunc(orig_fopen, this, filename, mode);
                } else {
                    result = orig_fopen(filename, mode);
                    Flog.i(`[fopen] Result: ` + result);
                }
                return result;
            }, 'pointer', ['pointer', 'pointer']));
        } else {
            Flog.e("Unable to find [fopen] function address.");
        }
    }

    /**
     * 监控fork函数
     * @param cbFunc    可选，回调函数
     * @param printBacktraceFlag   是否打印调用栈
     */
    function watch_fork(cbFunc: (origFunc: NativeFunction<number, []>, cbCtx: CallbackContext) => number = null, printBacktraceFlag: boolean = false) {
        const fork_addr = Module.findExportByName("libc.so", "fork");
        if (fork_addr) {
            let orig_fork = new NativeFunction(fork_addr, 'int', []);  // fork无参数
            Interceptor.replace(fork_addr, new NativeCallback(function () {
                let result;
                if (printBacktraceFlag) {
                    printBacktrace(`[fork] called`, this.context);
                } else {
                    Flog.i(`[fork] called`);
                }
                if (cbFunc) {
                    result = cbFunc(orig_fork, this);
                } else {
                    result = orig_fork();
                    Flog.i(`[fork] Result: ` + result);
                }
                return result;
            }, 'int', []));
        } else {
            Flog.e("Unable to find [fork] function address.");
        }
    }

    /**
     * 监控strstr函数
     * @param cbFunc 可选，回调函数
     * @param printBacktraceFlag
     */
    function watch_strstr(cbFunc: (cbCtx: InvocationContext, haystack_str: string, needle_str: string) => boolean = null, printBacktraceFlag: boolean = false) {
        const strstr_addr = Module.findExportByName("libc.so", "strstr");
        if (strstr_addr) {
            Interceptor.attach(strstr_addr, {
                onEnter: function (args) {
                    let haystack_str = args[0].readUtf8String();
                    let needle_str = args[1].readUtf8String();
                    if (printBacktraceFlag) {
                        printBacktrace(`[strstr] ${needle_str} in-> ${haystack_str}`, this.context);
                    } else {
                        Flog.i(`[strstr] ${needle_str} in-> ${haystack_str}`);
                    }
                    if (cbFunc) {
                        this.need_replace = cbFunc(this, haystack_str, needle_str)
                    }
                }, onLeave: function (retval) {
                    let resultStr = "False";
                    if (retval != ptr(0)) {
                        resultStr = "Found at: " + retval.readUtf8String();
                    }
                    if (this.need_replace) {
                        retval.replace(ptr(0));
                        resultStr += "; Replaced NULL."
                    }
                    Flog.i(`[strstr] Result: ${resultStr}`);
                }
            })
        } else {
            Flog.e("Unable to find [strstr] function address.");
        }
    }


    /**
     * 监控SVC调用
     * @param soname
     */
    function watch_svc(soname: string = "libc.so") {
        type SvcHook = {
            name: string;
            callback: InvocationListenerCallbacks | InstructionProbeCallback;
        };
        let svc_map_arm64: Map<number, SvcHook> = new Map();
        svc_map_arm64.set(56, {
            name: "__NR_openat", callback: {
                onEnter: function (args) {
                    let path = args[1].readCString();
                    Flog.i(`onEnter_SVC __NR_openat ${path}`);
                }, onLeave: function (retval) {
                    // Flog.i(`onLeave_SVC __NR_openat retval=${retval}`);
                }
            }
        }).set(48, {
            name: "__NR_faccessat", callback: {
                onEnter: function (args) {
                    let path = args[1].readCString();
                    Flog.i(`onEnter_SVC __NR_faccessat ${path}`);
                }, onLeave: function (retval) {
                    // Flog.i(`onLeave_SVC __NR_faccessat retval=${retval}`);
                }
            }
        });
        let svc_code_hex;
        let arch = Process.arch;
        if ("arm" === arch) {
            svc_code_hex = "00 00 00 EF";
        } else if ("arm64" === arch) {
            svc_code_hex = "01 00 00 D4";
        } else {
            Flog.e("arch not support!")
            return;
        }
        Process.enumerateRanges('r--').forEach(function (range) {
            if (!range.file || !range.file.path) {
                return;
            }
            let range_path = range.file.path;
            if (!range_path.includes(soname)) {
                return;
            }
            let baseAddr = Module.getBaseAddress(range_path);
            let soName = range_path.split('/').pop();
            Memory.scan(range.base, range.size, svc_code_hex, {
                onMatch: function (match, size) {
                    let svc_addr = match;
                    if (svc_addr.toUInt32() % 4 !== 0) {
                        Flog.w(`svc_addr ${svc_addr} is not aligned to 4 bytes, skip.`);
                        return;
                    }
                    let svc_number = 0;
                    if ("arm64" === arch) {
                        svc_number = ((svc_addr.sub(0x4).readS32()) >> 5) & 0xFFFF;
                    } else if ("arm" === arch) {
                        svc_number = (svc_addr.sub(0x4).readS32()) & 0xFFF;
                    } else {
                        Flog.e(`arch ${arch} not support!`)
                        return;
                    }
                    Flog.d(`[svc] ${soName} ${svc_addr}(${svc_addr.sub(baseAddr)}) svc_number=${svc_number}`);

                    if ("arm64" === arch) {
                        if (svc_map_arm64.has(svc_number)) {
                            let svc_info = svc_map_arm64.get(svc_number);
                            Interceptor.attach(svc_addr, svc_info.callback);
                        } else {
                            // Flog.w(`[svc] ${soName} svc_number=${svc_number} not found in map.`);
                        }
                    } else if ("arm" === arch) {
                        // none
                    }
                }
            })
        })
    }


    /**
     * 监控dlsym函数
     * @param soname 要hook的so的名称
     * @param cbFunc 回调函数，接收原始dlsym函数、句柄和符号地址；可以自己处理逻辑
     * @param printBacktraceFlag 是否打印栈回溯
     */
    function watch_dlsym(soname: string, cbFunc: (origFunc: NativeFunction<NativePointer, [NativePointer, NativePointer]>, cbCtx: CallbackContext, handle: NativePointer, symbol: NativePointer) => NativePointer = null, printBacktraceFlag: boolean = false) {
        const dlsym_addr = Module.findExportByName("libdl.so", "dlsym");
        if (dlsym_addr) {
            let orig_dlsym = new NativeFunction(dlsym_addr, 'pointer', ['pointer', 'pointer']);
            soHookerHandler.addHooker(soname, (soModule) => {
                Interceptor.replace(dlsym_addr, new NativeCallback(function (handle, symbol) {
                    let result;
                    let symbolStr = symbol.readCString();
                    if (printBacktraceFlag) {
                        printBacktrace(`[dlsym] (${symbolStr})`, this.context)
                    } else {
                        Flog.i(`[dlsym] ${symbolStr}`)
                    }
                    if (cbFunc) {
                        result = cbFunc(orig_dlsym, this, handle, symbol);
                    } else {
                        result = orig_dlsym(handle, symbol);
                        Flog.i(`[dlsym] ${symbolStr} returned: ` + result);
                    }
                    return result;
                }, 'pointer', ['pointer', 'pointer']));
            })
        } else {
            Flog.e("Unable to find [dlsym] function address.");
        }
    }


    /**
     * 监控RegisterNatives动态注册
     * 来自 https://github.com/lasting-yang/frida_hook_libart
     */
    function watch_RegisterNatives() {
        function hook_RegisterNatives(addrRegisterNatives) {
            if (addrRegisterNatives != null) {
                Interceptor.attach(addrRegisterNatives, {
                    onEnter: function (args) {
                        console.log("[RegisterNatives] method_count:", args[3]);
                        var env = args[0];
                        var java_class = args[1];
                        var class_name = Java.vm.tryGetEnv().getClassName(java_class);
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


    return {

        watch_so_load,
        watch_pthread_create,
        watch_RegisterNatives,
        watch_strstr,
        watch_access,
        watch_fork,
        watch_fopen,
        watch_open,
        watch_openat,
        watch_svc,
        watch_dlsym,
    }
})()