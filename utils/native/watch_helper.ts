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
}
