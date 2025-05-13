import {SoHookerHandler} from "./native/SoHookerHandler";
import {Flog} from "./Flog";
import {AHelper} from "./AHelper";

/**
 * Android 帮助类
 */
export namespace NHelper {

    /**
     * 在so初始化之前hook（只能hook一个so）
     * @param soname 要hook的so的名称，如libxxx.so
     * @param callback 自定义需要执行的回调函数
     */
    export function hookBeforeSoInit(soname: string, callback: (soModule: Module) => void): void {
        let hooked = false;
        let linker_m;
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
     * hook控制，管理所有SoHook任务
     * @private
     */
    const hookerHandler: SoHookerHandler = new SoHookerHandler();

    /**
     * 获取So Hook控制器
     * @returns {SoHookerHandler} SoHookerHandler对象
     */
    export function getSoHookerHandler(): SoHookerHandler {
        return hookerHandler;
    }


    /**
     * 获得栈回溯字符串
     * @param context 上下文，不支持忽略
     * @param modeFlag true=FUZZY
     */
    export function getBacktrace(context: CpuContext, modeFlag: boolean = false): string {
        let mode = modeFlag ? Backtracer.FUZZY : Backtracer.ACCURATE;
        let throwable = Thread.backtrace(context, mode)
            .map(DebugSymbol.fromAddress).join('\n');
        return throwable;
    }

    /**
     * 打印栈回溯
     * @param TAG TAG，可选
     * @param context 上下文
     * @param modeFlag true=FUZZY
     */
    export function printBacktrace(TAG: string = "", context: CpuContext, modeFlag: boolean = false): void {
        console.log("========================================  " + TAG + " backtrace strat  ========================================");
        console.log(getBacktrace(context, modeFlag));
        console.log("=========================================  " + TAG + " backtrace end  =========================================\r\n");
    }

    /**
     * 从std::string对象中取到str
     * @param strPtr 地址指针
     */
    export function getStdStringStr(strPtr: NativePointer): string {
        let isTiny = (strPtr.readU8() & 1) === 0;
        if (isTiny) {
            return strPtr.add(1).readUtf8String();
        }
        return strPtr
            .add(2 * Process.pointerSize)
            .readPointer()
            .readUtf8String();
    }

    /**
     * 从jstring对象中取到str
     * @param strPtr 地址指针
     */
    export function getJstringStr(strPtr: NativePointer): string {
        return Java.vm.getEnv().getStringUtfChars(strPtr, null).readCString();
    }

    /**
     * 新建一个jstring对象
     * @param str 字符串值
     */
    export function newJstring(str: string): NativePointer {
        return Java.vm.getEnv().newStringUtf(str);
    }

    /**
     * 写内容到指定文件（需有权限）
     * @param filename 输出文件的全路径
     * @param contents 要输出的内容
     */
    export function writeFile(filename: string = "/data/local/tmp/ooout.txt", contents: string) {
        let fopen_addr = Module.getExportByName("libc.so", "fopen");
        let fputs_addr = Module.getExportByName("libc.so", "fputs");
        let fclose_addr = Module.getExportByName("libc.so", "fclose");

        let fopen = new NativeFunction(fopen_addr, "pointer", ["pointer", "pointer"]);
        let fputs = new NativeFunction(fputs_addr, "int", ["pointer", "pointer"]);
        let fclose = new NativeFunction(fclose_addr, "int", ["pointer"]);

        let fileName = Memory.allocUtf8String(filename);
        let mode = Memory.allocUtf8String("a+");
        let fp = fopen(fileName, mode);
        let contentHello = Memory.allocUtf8String(contents);
        let ret = fputs(contentHello, fp);

        fclose(fp);
        Flog.i(`writeFile(${fileName}) done. return ${ret}`)
    }


    /**
     * ARM64 NOP指定地址
     * @param ptrAddr 要NOP的地址
     */
    export function nop_arm64(ptrAddr) {
        const address = ptr(ptrAddr);
        Memory.patchCode(address, 4, code => {
            const writer = new Arm64Writer(code, {pc: address});
            writer.putNop();
            writer.flush();
        });

        Flog.d('ARM NOP patched at: ' + address);
    }

    /**
     * thumb NOP指定地址
     * @param ptrAddr 要NOP的地址
     */
    export function nop_thumb(ptrAddr) {
        const address = ptr(ptrAddr);
        Memory.patchCode(address, 2, code => {
            const writer = new ThumbWriter(code, {pc: address});
            writer.putNop();
            writer.flush();
        });

        Flog.d('Thumb NOP patched at: ' + address);
    }


    /**
     * 监控so的加载
     * @param printBacktraceFlag 是否打印栈回溯
     */
    export function watchSoLoad(printBacktraceFlag: boolean = false) {
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
     * 监控新线程的创建
     */
    export function watch_pthread_create(soname: string, callback: (soModule: Module) => void = (soModule) => {
    }) {
        let pthread_create_addr = Module.findExportByName("libc.so", "pthread_create");
        getSoHookerHandler().addHooker(soname, (soModule) => {
            if (pthread_create_addr) {
                Interceptor.attach(pthread_create_addr, {
                    onEnter: function (args) {
                        Flog.i(`pthread_create offset: ${args[2].sub(soModule.base)}`)
                    },
                    onLeave: function (retval) {
                        Flog.d("pthread_create returned: " + retval);
                    }
                });
            } else {
                Flog.e("Unable to find pthread_create function address.");
            }
            callback(soModule)
        })
        // TODO: NO TEST
        // .update()
    }


    /**
     * 监控RegisterNatives动态注册
     * 来自 https://github.com/lasting-yang/frida_hook_libart
     */
    export function watch_RegisterNatives() {
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

    /**
     * 获取native方法的动态注册地址
     * @param method Java.Method对象
     */
    export function printMethodAddr(method) {
        let artmethod: NativePointer = null;
        try {
            artmethod = method.$handle;
        } catch (e) {
        }
        if (artmethod == null) {
            try {
                artmethod = method.$h;
            } catch (e) {
            }
        }
        if (artmethod == null) {
            try {
                artmethod = method.handle;
            } catch (e) {
            }
        }
        if (artmethod == null) {
            Flog.e(`printMethodAddr: ${method.methodName} artmethod is null.`);
            return;
        }
        let i = 0;
        let native_addr = null;
        let soModule = null;
        for (i = 0; i < 5; i++) {
            try {
                // .add(16)
                native_addr = artmethod.add(i * Process.pointerSize).readPointer();
                soModule = Process.findModuleByAddress(native_addr);
                if (!soModule) {
                    continue;
                }

                if (soModule.path.startsWith("/data/app/")) {
                    Flog.i(`find ${method.methodName}, soModule=${JSON.stringify(soModule)}\n\tnative_addr=${native_addr}, offset=${native_addr.sub(soModule.base)}`);
                    break;
                }
            } catch (e) {
            }
        }
    }


}