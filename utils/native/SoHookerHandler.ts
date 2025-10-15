import {Flog} from "../Flog";

/**
 * SoHooker对象，每个Hook的so有一个这对象对应
 */
class SoHooker {
    public soName: string;
    public callbacks: Array<(soModule: Module) => void>;
    public isHooked: boolean;

    constructor(
        soName: string,
        isHooked: boolean = false
    ) {
        this.soName = soName;
        this.callbacks = [];
        this.isHooked = isHooked;
    }

    /**
     * 更新so Hook
     * @param callback 执行的hook逻辑
     */
    update(callback: (soModule: Module) => void) {
        if (!this.callbacks.includes(callback)) {
            this.callbacks.push(callback);
            Flog.d("SoHooker", `Hooker ${this.soName} add callback.`);
        } else {
            // Flog.d("SoHooker", `The callback has been added.`)
        }
        this.isHooked = false;
    }

}

/**
 * hook控制，管理所有SoHook任务
 */
class SoHookerHandlerImpl {
    readonly TAG: string = "SoHookerHandler";
    /**
     * 存储soHook任务
     * @protected
     */
    protected hookers: SoHooker[] = [];

    constructor() {
        this.hookers = []
        this.hookBeforeSoInit()
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
            let newHooker = new SoHooker(soName, false);
            newHooker.update(callback);
            this.hookers.push(newHooker);
        }
        return this;
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
        Flog.d(this.TAG, `removeHooker: ${soName}`)
        return this;
    }

    /**
     * 清除所有soHooker
     */
    clearHookers() {
        this.hookers = []
        Flog.d(this.TAG, `clearHookers`)
        return this;
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
     * 执行所有Hook的回调
     * @param func
     */
    private invokeCb(func: (soname: string, callback: Array<(soModule: Module) => void>, isHooked: boolean, index: number) => void) {
        for (let i = 0; i < this.hookers.length; i++) {
            func(this.hookers[i].soName, this.hookers[i].callbacks, this.hookers[i].isHooked, i);
        }
    }

    /**
     * 执行完某个Hooker，设置其已经被hook，避免多次hook
     * @param index
     */
    private doneHooker(index: number) {
        this.hookers[index].isHooked = true;
    }

    /**
     * 打印所有Hooker
     */
    printAllHooker() {
        console.log("==> PrintAllHooker:")
        for (let i = 0; i < this.hookers.length; i++) {
            console.log(`[${i}] ${this.hookers[i].soName} has ${this.hookers[i].callbacks.length} callbacks, isHooked: ${this.hookers[i].isHooked}`);
        }
        console.log("<== PrintAllHooker done.")
    }


    /**
     * Hook实际执行的函数
     * @private
     */
    private hookBeforeSoInit(): void {
        const self = this;
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
        // Flog.d(TAG, `The [linker] has been hooked.`)
        for (let i = 0; i < symbols.length; i++) {
            let sym_name = symbols[i].name;
            if (sym_name.includes(`soinfo`) && sym_name.includes(`call_constructors`)) {
                call_constructors_addr = symbols[i].address;
                break;
            }
        }
        Interceptor.attach(call_constructors_addr, {
            onEnter: function (args) {
                // Flog.d(TAG, `Called call_constructors`)
                self.invokeCb((soname, callbacks, isHooked, index) => {
                    let so = Process.findModuleByName(soname)
                    if (so && !isHooked) {
                        callbacks.forEach(cb => cb(so));
                        self.doneHooker(index)
                    }
                })
            }
        })
    }
}

export const soHookerHandler = new SoHookerHandlerImpl();