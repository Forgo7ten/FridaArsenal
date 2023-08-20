import {common} from "../common";
import Flog = common.Flog;

export class _NHookHelper {
    static readonly TAG: string = "NHookHelper";

    /**
     * 在so初始化之前hook
     * TODO: 目前只能hook一个so，可以添加一个Map数组改写成hook多个so、执行多个回调函数（addHookBeforeSoInit）
     * @param soname 要hook的so的名称，如libxxx.so
     * @param callback 自定义需要执行的回调函数
     */
    static hookBeforeSoInit(soname: string, callback: () => void): void {
        let linker_m = Process.findModuleByName("linker");
        let linker64_m = Process.findModuleByName("linker64");
        let call_constructors_addr = null;
        let hooked = false;
        let symbols;
        if (linker_m) {
            symbols = linker_m.enumerateSymbols();
            Flog.i(_NHookHelper.TAG, `The [linker] has been hooked.`)
        } else if (linker64_m) {
            symbols = linker64_m.enumerateSymbols();
            Flog.i(_NHookHelper.TAG, `The [linker64] has been hooked.`)
        } else {
            Flog.e(_NHookHelper.TAG, `No [linker] or [linker64] found.`)
            return;
        }
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
                if (Process.findModuleByName(soname) && !hooked) {
                    callback();
                    hooked = true;
                }
            }
        })
    }

}