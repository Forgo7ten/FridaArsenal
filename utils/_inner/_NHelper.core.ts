import {Flog} from "../Flog";

export const _NHelperCore = (() => {

        let noDebugSymbolFlag = false;

        function noDebugSymbol() {
            noDebugSymbolFlag = true;
        }

        function fmt(addr) {
            return '0x' + ptr(addr).toString(16);
        }

        function getModuleByAddr(addrInMem: NativePointer) {
            Process.enumerateModules().forEach(module => {
                if (addrInMem.compare(module.base) >= 0 && addrInMem.compare(module.base.add(module.size))) {
                    return module;
                }
            })
            return null
        }

        /**
         * 获得栈回溯字符串
         * @param context 上下文，不支持忽略
         * @param modeFlag true=FUZZY
         */
        function getBacktrace(context: CpuContext, modeFlag: boolean = false): string {
            let mode = modeFlag ? Backtracer.FUZZY : Backtracer.ACCURATE;
            if (noDebugSymbolFlag) {
                return Thread.backtrace(context, mode)
                    .map((addr) => {
                        let so_module = getModuleByAddr(addr);
                        `${fmt(addr)} is in ${so_module.name} offset: ${fmt(addr.sub(so_module.base))}`
                    }).join('\n');
            } else {
                return Thread.backtrace(context, mode)
                    .map(DebugSymbol.fromAddress).join('\n');
            }
        }

        /**
         * 打印栈回溯
         * @param TAG TAG，可选
         * @param context 上下文
         * @param modeFlag true=FUZZY
         */
        function printBacktrace(TAG: string = "", context: CpuContext, modeFlag: boolean = false): void {
            Flog.i("printBacktrace\n"
                + "========================================  " + TAG + " backtrace strat  ========================================\n"
                + getBacktrace(context, modeFlag) + "\n"
                + "=========================================  " + TAG + " backtrace end  =========================================\r\n");
        }


        /**
         * patch指定地址，写入nop指令
         * @param addr
         */
        function patch_nop(addr) {
            let address = (addr instanceof NativePointer) ? addr : ptr(addr);
            let arch = "arm64"
            if (Process.arch === 'arm64') {
                arch = "arm64";
            } else {
                arch = address.and(1).toInt32() === 1 ? "thumb" : "arm";
                if (arch === "thumb") address = address.and(ptr(-2));
            }
            const size = (arch === "thumb") ? 2 : 4;
            Memory.patchCode(address, size, code => {
                const Writer = {
                    "arm64": Arm64Writer,
                    "arm": ArmWriter,
                    "thumb": ThumbWriter
                }[arch];

                const writer = new Writer(code, {pc: address});
                writer.putNop();
                writer.flush();
            });

            Flog.d(`${arch} NOP patched at: ` + address);
        }

        function patch_func_ret(func_addr) {
            let address = (func_addr instanceof NativePointer) ? func_addr : ptr(func_addr);
            if (Process.arch === 'arm64') {
                let arch = "arm64";
                let size = 4;
                Memory.patchCode(address, size, code => {
                    const writer = new Arm64Writer(code, {pc: address});
                    writer.putRet();
                    writer.flush();
                });
                Flog.d(`${arch} RET patched at: ` + address);
            }
        }


        /**
         * 写内容到指定文件（需有权限）
         * @param outFilePath 输出文件的全路径
         * @param buffer 要输出的内容，可以是字符串或ArrayBuffer
         */
        function writeFile(outFilePath: string, buffer: ArrayBuffer | string) {
            let fopen = new NativeFunction(Module.getExportByName(null, 'fopen'), 'pointer', ['pointer', 'pointer']);
            let fwrite = new NativeFunction(Module.getExportByName(null, 'fwrite'), 'ulong', ['pointer', 'ulong', 'ulong', 'pointer']);
            let fclose = new NativeFunction(Module.getExportByName(null, 'fclose'), 'int', ['pointer']);
            let filePathPtr = Memory.allocUtf8String(outFilePath);
            let modePtr = Memory.allocUtf8String('wb');
            let filePtr = fopen(filePathPtr, modePtr);
            if (filePtr.isNull()) {
                throw new Error('Failed to open file: ' + outFilePath);
            }
            try {
                let dataPtr: NativePointer, dataSize: number;
                if (typeof buffer === 'string') {
                    // 如果是字符串，转换为字节数组
                    dataSize = buffer.length + 1;
                    dataPtr = Memory.alloc(dataSize);
                    dataPtr.writeUtf8String(buffer);
                } else {
                    dataSize = buffer.byteLength;
                    dataPtr = Memory.alloc(dataSize);
                    dataPtr.writeByteArray(buffer);
                }
                let written = fwrite(dataPtr, 1, dataSize, filePtr);
                if (written != dataSize) {
                    throw new Error('Failed to write all data to file (' + written + '/' + dataSize + ')');
                }
            } finally {
                fclose(filePtr);
            }
        }


        return {
            noDebugSymbol,
            getModuleByAddr,
            getBacktrace,
            printBacktrace,
            patch_nop,
            patch_func_ret,
            writeFile,
        }
    }

)
()