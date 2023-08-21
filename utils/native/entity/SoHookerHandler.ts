import {_NHookHelper} from "../hook_helper";
import {common} from "../../common";
import Flog = common.Flog;

/**
 * SoHooker对象，每个Hook的so有一个这对象对应
 */
class SoHooker {
    public soName: string;
    public hookInvoke: (soModule: Module) => void;
    public isHooked: boolean;

    constructor(
        soName: string,
        hookInvoke: (soModule: Module) => void,
        isHooked: boolean = false
    ) {
        this.soName = soName;
        this.hookInvoke = hookInvoke;
        this.isHooked = isHooked;
    }

    /**
     * 更新so Hook
     * @param hookInvoke
     */
    update(hookInvoke: (soModule: Module) => void) {
        this.hookInvoke = hookInvoke;
        this.isHooked = false;
    }

}

/**
 * hook控制，管理所有SoHook任务
 */
export class SoHookerHandler {
    static readonly TAG: string = "SoHookerHandler";
    /**
     * 存储soHook任务
     * @protected
     */
    protected hookers: SoHooker[] = [];
    /**
     * 判断是否需要更新
     * @protected
     */
    protected need_update = false;

    constructor() {
        this.hookers = []
    }

    /**
     * 添加一个so Hooker
     * @param soName so名称
     * @param callback 执行的hook逻辑
     */
    addHooker(soName: string, callback: (soModule: Module) => void) {
        let anyHooker = this.getHooker(soName);
        if (anyHooker) {
            anyHooker.update(callback);
        } else {
            this.hookers.push(new SoHooker(soName, callback, false));
        }
        this.needUpdate()
        Flog.d(SoHookerHandler.TAG, `addHooker: ${soName}`)
    }

    /**
     * 移除一个soHooker
     * @param soName so名称
     */
    removeHooker(soName: string) {
        for (let i = 0; i < this.hookers.length; i++) {
            if (this.hookers[i].soName === soName) {
                this.hookers.splice(i, 1)
                break;
            }
        }
        this.needUpdate()
        Flog.d(SoHookerHandler.TAG, `removeHooker: ${soName}`)
    }

    /**
     * 清除所有soHooker
     */
    clearHookers() {
        this.hookers = []
        this.needUpdate()
        Flog.d(SoHookerHandler.TAG, `clearHookers`)

    }

    /**
     * 通过soName拿到一个SoHooker
     * @param soName
     */
    getHooker(soName: string): SoHooker {
        for (let i = 0; i < this.hookers.length; i++) {
            if (this.hookers[i].soName === soName) {
                return this.hookers[i];
            }
        }
        return null;
    }

    /**
     * 判断是否需要更新
     */
    isNeedUpdate(): boolean {
        return this.need_update;
    }

    /**
     * 需要更新，设置更新标志位并重新Hook以应用更新
     */
    needUpdate() {
        this.need_update = true;
        SoHookerHandler.hookBeforeSoInit(this);
    }

    /**
     * 所有执行完了后更新need_update标志位
     */
    allDone() {
        this.need_update = false;
    }

    /**
     * 执行所有Hook的回调
     * @param func
     */
    invokeCb(func: (soname: string, callback: (soModule: Module) => void, isHooked: boolean, index: number) => void) {
        for (let i = 0; i < this.hookers.length; i++) {
            func(this.hookers[i].soName, this.hookers[i].hookInvoke, this.hookers[i].isHooked, i);
        }
    }

    /**
     * 执行完某个Hooker，设置其已经被hook，避免多次hook
     * @param index
     */
    doneHooker(index: number) {
        this.hookers[index].isHooked = true;
    }

    /**
     * 打印所有Hooker
     */
    printAllHooker() {
        console.log("==> PrintAllHooker:")
        for (let i = 0; i < this.hookers.length; i++) {
            console.log(`[${i}] ${this.hookers[i].soName}`)
        }
        console.log("<== PrintAllHooker done.")
    }


    /**
     * Hook实际执行的函数
     * @protected
     */
    protected static hookBeforeSoInit(hookerHandler): void {
        if (!hookerHandler.isNeedUpdate()) {
            return;
        }
        let linker_m = Process.findModuleByName("linker");
        let linker64_m = Process.findModuleByName("linker64");
        let call_constructors_addr = null;
        let symbols;
        if (linker64_m) {
            symbols = linker64_m.enumerateSymbols();
            // Flog.d(_NHookHelper.TAG, `The [linker64] has been hooked.`)
        } else if (linker_m) {
            symbols = linker_m.enumerateSymbols();
            // Flog.d(_NHookHelper.TAG, `The [linker] has been hooked.`)
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
                hookerHandler.invokeCb((soname, callback, isHooked, index) => {
                    let so = Process.findModuleByName(soname)
                    if (so && !isHooked) {
                        callback(so);
                        hookerHandler.doneHooker(index)
                    }
                })
            }
        })
        hookerHandler.allDone();
    }
}