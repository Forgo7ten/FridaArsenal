import {SoHookerHandler} from "./entity/SoHookerHandler";
import {common} from "../common";
import Flog = common.Flog;

export class _NHookHelper {
    static readonly TAG: string = "NHookHelper";

    /**
     * 在so初始化之前hook（只能hook一个so，尽量使用addHookBeforeSoInit）
     * @param soname 要hook的so的名称，如libxxx.so
     * @param callback 自定义需要执行的回调函数
     */
    static hookBeforeSoInitOld(soname: string, callback: (soModule: Module) => void): void {
        let hooked = false;
        let linker_m;
        if (Process.pointerSize == 4) {
            linker_m = Process.findModuleByName("linker");
        } else if(Process.pointerSize == 8){
            linker_m = Process.findModuleByName("linker64");
        }else {
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
     * @protected
     */
    protected static hookerHandler: SoHookerHandler = new SoHookerHandler();

    /**
     * 添加对某个so的hook
     * 好像只能用地址偏移查找
     * @param soname 要hook的so的名称，如libxxx.so
     * @param callback 自定义需要执行的回调函数
     */
    static addHookBeforeSoInit(soname: string, callback: (soModule: Module) => void): void {
        this.hookerHandler.addHooker(soname, callback);
    }

    static removeHookBeforeSoInit(soname: string): void {
        this.hookerHandler.removeHooker(soname);
    }

    static clearHooksBeforeSoInit(): void {
        this.hookerHandler.clearHookers();
    }

}