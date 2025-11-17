import {Flog} from "../Flog";

/**
 * 回调时机枚举
 * @internal
 */
export enum CallbackTime {
    beforeSoInit = "beforeSoInit",
    afterSoLoad = "afterSoLoad"
}

/**
 * Callback类，用于区分不同的回调时机
 * @internal
 */
class Callback {
    public time: CallbackTime;
    public run: (soModule: Module) => void;

    constructor(type: CallbackTime, callback: (soModule: Module) => void) {
        this.time = type;
        this.run = callback;
    }
}

/**
 * SoHooker对象，每个Hook的so有一个这对象对应
 * @internal
 */
class SoHooker {
    public soName: string;
    public callbacks: Array<Callback>;

    /**
     * beforeSoInit时机的callback是否已执行
     */
    public isBeforeSoInitDone: boolean;

    /**
     * afterSoLoad时机的callback是否已执行
     */
    public isAfterSoLoadDone: boolean;

    constructor(soName: string) {
        this.soName = soName;
        this.callbacks = [];
        this.isBeforeSoInitDone = false;
        this.isAfterSoLoadDone = false;
    }

    /**
     * 更新so Hook
     * @param callback 执行的hook逻辑
     * @param time 回调时机类型
     */
    update(callback: (soModule: Module) => void, time: CallbackTime) {
        const existingCallback = this.callbacks.find(cb => cb.run === callback && cb.time === time);
        if (!existingCallback) {
            this.callbacks.push(new Callback(time, callback));
            Flog.d("SoHooker", `Hooker ${this.soName} add callback on ${time}.`);
        } else {
            // Flog.d("SoHooker", `The callback has been added.`)
        }
    }

    /**
     * 检查是否有指定类型的callback
     */
    hasCallbackType(time: CallbackTime): boolean {
        return this.callbacks.some(cb => cb.time === time);
    }

    /**
     * 获取指定类型的所有callback
     */
    getCallbacksByType(time: CallbackTime): Callback[] {
        return this.callbacks.filter(cb => cb.time === time);
    }

    /**
     * 检查指定类型的callback是否已执行
     */
    isDone(time: CallbackTime): boolean {
        if (time === CallbackTime.beforeSoInit) {
            return this.isBeforeSoInitDone;
        } else {
            return this.isAfterSoLoadDone;
        }
    }

    /**
     * 标记指定类型的callback已执行
     */
    setDone(time: CallbackTime) {
        if (time === CallbackTime.beforeSoInit) {
            this.isBeforeSoInitDone = true;
        } else {
            this.isAfterSoLoadDone = true;
        }
    }

    /**
     * 重置执行状态（用于so重新加载的场景）
     */
    reset() {
        this.isBeforeSoInitDone = false;
        this.isAfterSoLoadDone = false;
    }
}

/**
 * hook控制，管理所有SoHook任务
 */
export class SoHookerHandlerImpl {
    readonly TAG: string = "SoHookerHandler";

    /**
     * 存储soHook任务
     * @private
     */
    private hookers: Map<string, SoHooker> = new Map();

    /**
     * 当前正在加载的so路径集合
     * @private
     */
    private loadingSoMap: Map<number, string> = new Map();


    /**
     * 初始化AfterSoLoad标记
     * @private
     */
    private isInitializedA: boolean = false;
    /**
     * 初始化BeforeSoInit标记
     * @private
     */
    private isInitializedB: boolean = false;

    constructor() {
        this.isInitializedA = false;
        this.isInitializedB = false;
    }

    /**
     * 初始化hook
     * @private
     */
    private initializeHooks() {
        if (!this.isInitializedA) {
            this.isInitializedA = true;
            this.hookAfterSoLoad();
            Flog.d(this.TAG, "Hooks AfterSoLoad initialized.");
        }
        if (!this.isInitializedB) {
            this.isInitializedB = true;
            this.hookBeforeSoInit();
            Flog.d(this.TAG, "Hooks BeforeSoInit initialized.");
        }
    }

    /**
     * 添加一个so Hooker (AfterSoLoad时机)
     * @param soName so名称
     * @param callback 执行的hook逻辑
     */
    addHookerAfterSoLoad(soName: string, callback: (soModule: Module) => void) {
        return this.addHookerInner(soName, callback, CallbackTime.afterSoLoad);
    }

    /**
     * 添加一个so Hooker (BeforeSoInit时机)
     * @param soName so名称
     * @param callback 执行的hook逻辑
     */
    addHookerBeforeSoInit(soName: string, callback: (soModule: Module) => void) {
        return this.addHookerInner(soName, callback, CallbackTime.beforeSoInit);
    }

    /**
     * 内部方法：添加hooker
     * @private
     */
    private addHookerInner(soName: string, callback: (soModule: Module) => void, time: CallbackTime) {
        this.initializeHooks();
        let anyHooker = this.getHooker(soName);
        if (anyHooker) {
            anyHooker.update(callback, time);
        } else {
            let newHooker = new SoHooker(soName);
            newHooker.update(callback, time);
            this.hookers.set(soName, newHooker);
        }
        return this;
    }

    /**
     * 移除一个soHooker
     * @param soName so名称
     */
    removeHooker(soName: string) {
        this.hookers.delete(soName);
        Flog.d(this.TAG, `removeHooker: ${soName}`);
        return this;
    }

    /**
     * 重置指定hooker的执行状态
     * 用于so被卸载后重新加载的场景
     * @param soName so名称
     */
    resetHooker(soName: string) {
        let hooker = this.getHooker(soName);
        if (hooker) {
            hooker.reset();
            Flog.d(this.TAG, `resetHooker: ${soName}`);
        }
        return this;
    }

    /**
     * 清除所有soHooker
     */
    clearHookers() {
        this.hookers.clear();
        Flog.d(this.TAG, `clearHookers`);
        return this;
    }

    /**
     * 通过soName拿到一个SoHooker
     * @param soName
     */
    getHooker(soName: string): SoHooker | null {
        return this.hookers.get(soName) || null;
    }

    /**
     * 执行指定类型的Hook回调
     * @param callbackTime 回调时机类型
     * @param currentLoadSoPath 当前so的完整路径
     * @private
     */
    private invokeCb(callbackTime: CallbackTime, currentLoadSoPath: string) {
        if (!currentLoadSoPath) return;
        for (const hooker of this.hookers.values()) {
            // 检查是否有对应类型的callback
            if (!hooker.hasCallbackType(callbackTime) || hooker.isDone(callbackTime)) {
                continue;
            }
            if (!this.isSoNameMatch(currentLoadSoPath, hooker.soName)) continue;
            const soModule = Process.findModuleByName(hooker.soName);
            if (!soModule) {
                Flog.w(this.TAG, `Module ${hooker.soName} not found in memory for ${callbackTime} callbacks.`);
                continue;
            }
            const targetCallbacks = hooker.getCallbacksByType(callbackTime);
            targetCallbacks.forEach(cb => {
                try {
                    cb.run(soModule);
                } catch (e) {
                    Flog.e(this.TAG, `Callback execution error for ${hooker.soName} (${callbackTime}): ${e}`);
                }
            });
            hooker.setDone(callbackTime);
        }
    }

    /**
     * 打印所有Hooker
     */
    printAllHooker() {
        console.log("==> PrintAllHooker:");
        let hookerArray = Array.from(this.hookers.values());
        for (let i = 0; i < hookerArray.length; i++) {
            const hooker = hookerArray[i];
            const beforeInitCount = hooker.getCallbacksByType(CallbackTime.beforeSoInit).length;
            const afterLoadCount = hooker.getCallbacksByType(CallbackTime.afterSoLoad).length;
            console.log(
                `[${i}] ${hooker.soName}: ` +
                `total=${hooker.callbacks.length}, ` +
                `beforeInit=${beforeInitCount}(done:${hooker.isBeforeSoInitDone}), ` +
                `afterLoad=${afterLoadCount}(done:${hooker.isAfterSoLoadDone})`
            );
        }
        console.log("<== PrintAllHooker done.");
    }

    /**
     * 检查so名称是否匹配
     * @param fullPath so的完整路径
     * @param soName 要匹配的so名称
     * @private
     */
    private isSoNameMatch(fullPath: string | null, soName: string): boolean {
        if (!fullPath) {
            return false;
        }
        return fullPath.endsWith("/" + soName) || fullPath === soName;
    }

    /**
     * Hook BeforeSoInit时机的函数
     * 在so的构造函数调用前执行
     * @private
     */
    private hookBeforeSoInit(): void {
        const self = this;
        let linker_m: Module | null = null;

        if (Process.pointerSize == 4) {
            linker_m = Process.findModuleByName("linker");
        } else if (Process.pointerSize == 8) {
            linker_m = Process.findModuleByName("linker64");
        } else {
            Flog.e(this.TAG, `Unsupported pointer size: ${Process.pointerSize}`);
            return;
        }

        if (!linker_m) {
            Flog.e(this.TAG, `Linker module not found.`);
            return;
        }

        let call_constructors_addr: NativePointer | null = null;
        let symbols = linker_m.enumerateSymbols();

        for (let i = 0; i < symbols.length; i++) {
            let sym_name = symbols[i].name;
            if (sym_name.includes(`soinfo`) && sym_name.includes(`call_constructors`)) {
                call_constructors_addr = symbols[i].address;
                Flog.d(this.TAG, `Found call_constructors at ${linker_m.path}!${call_constructors_addr.sub(linker_m.base)}`);
                break;
            }
        }

        if (call_constructors_addr) {
            Interceptor.attach(call_constructors_addr, {
                onEnter: function (args) {
                    const currentLoadSoPath = self.loadingSoMap.get(this.threadId);
                    if (currentLoadSoPath) {
                        self.invokeCb(CallbackTime.beforeSoInit, currentLoadSoPath);
                    }
                }
            });
        } else {
            Flog.e(this.TAG, "No 'call_constructors' symbol found.")
        }
    }

    /**
     * Hook AfterSoLoad时机的函数
     * 在so加载完成后执行
     * @private
     */
    private hookAfterSoLoad(): void {
        const self = this;
        /*
        let dlopen_np = Module.findExportByName("libdl.so", "dlopen");
        if (dlopen_np) {
            Interceptor.attach(dlopen_np, {
                onEnter: function (args) {
                    let filename = args[0].readCString();
                    let flag = args[1];
                }, onLeave: function (retval) {
                }
            })
            Flog.d("attach libdl.so -> dlopen(const char* filename, int flag)")
        }*/
        let android_dlopen_ext_np = Module.findExportByName("libdl.so", "android_dlopen_ext");
        if (android_dlopen_ext_np) {
            Interceptor.attach(android_dlopen_ext_np, {
                onEnter: function (args) {
                    let filename = args[0].readCString();
                    if (filename) {
                        this.sofilename = filename;
                        if (self.loadingSoMap.has(this.threadId)) {
                            Flog.w(self.TAG, `${filename}(${this.threadId}) already in loading map. Overwriting entry.`);
                        }
                        self.loadingSoMap.set(this.threadId, filename);
                        // Flog.d(self.TAG, `Added to loading map: ${filename}(${this.threadId}).`);
                    }
                },
                onLeave: function (retval) {
                    const currentSoPath = this.sofilename;
                    if (currentSoPath) {
                        try {
                            self.invokeCb(CallbackTime.afterSoLoad, currentSoPath);
                        } catch (e) {
                            Flog.e(self.TAG, `Critical error in afterSoLoad: ${e}`);
                        } finally {
                            self.loadingSoMap.delete(this.threadId);
                            // Flog.d(self.TAG, `Removed from loading set: ${currentSoPath}(${this.threadId}).`);
                        }
                    }
                }
            });
        } else {
            Flog.e(this.TAG, "android_dlopen_ext not found in libdl.so");
        }
    }
}

export const soHookerHandler = new SoHookerHandlerImpl();