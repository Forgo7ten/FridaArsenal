import {Flog} from "./Flog";
import {_NHelperCore} from "./_inner/_NHelper.core";
import {_NHelperHook} from "./_inner/_NHelper.hook";
import {_NHelperWatch} from "./_inner/_NHelper.watch";
import {_NHelperStr} from "./_inner/_NHelper.str";

const {writeFile} = _NHelperCore
/**
 * Native 帮助工具模块
 */
export const NHelper = (() => {

    /**
     * 获取native方法的动态注册地址
     * @param method Java.Method对象
     */
    function printMethodRegisterAddr(method) {
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

    /**
     * 从内存中dump出so文件
     * @param so so的名称或Module对象
     * @param pkg_or_dir 包名或输出目录
     */
    function dumpSo(so: string | Module, pkg_or_dir: string) {
        let soModule = null;
        if (typeof so === 'string') {
            soModule = Process.findModuleByName(so);
        } else {
            soModule = so;
        }
        if (!soModule) {
            Flog.e(`dumpSo: ${so} not found.`);
            return;
        }
        Memory.protect(soModule.base, soModule.size, 'rwx');
        let soBuffer = (soModule.base).readByteArray(soModule.size);
        let outDir = `/data/data/${pkg_or_dir}`
        if (pkg_or_dir.includes('/')) {
            outDir = pkg_or_dir;
        }
        let outFilePath = `${outDir}/${soModule.name}_${soModule.base}_${soModule.size}.dump`;
        writeFile(outFilePath, soBuffer);
        Flog.i(`dumpSo: ${soModule.name} dumped to ${outFilePath}`);
    }

    return {
        ..._NHelperCore,
        ..._NHelperStr,
        ..._NHelperHook,
        ..._NHelperWatch,
        printMethodRegisterAddr,
        dumpSo,
    };

})()