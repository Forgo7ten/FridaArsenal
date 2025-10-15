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
     * 添加一个So Hooker
     * @param soname
     * @param callback
     */
    function addHooker(soname: string, callback: (soModule: Module) => void) {
        return soHookerHandler.addHooker(soname, callback);
    }

    return {
        soHookerHandler,
        addHooker,
        hookBeforeSoInit

    }
})()