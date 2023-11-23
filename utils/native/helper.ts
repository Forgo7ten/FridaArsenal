import {common} from "../common";
import Flog = common.Flog;

export class _NHelper {

    /**
     * 获得栈回溯字符串
     * @param context 上下文，不支持忽略
     * @param modeFlag true=FUZZY
     */
    static getBacktrace(context: CpuContext, modeFlag: boolean = false): string {
        let mode = modeFlag ? Backtracer.FUZZY : Backtracer.ACCURATE;
        let throwable = Thread.backtrace(context, mode)
            .map(DebugSymbol.fromAddress).join('\n');
        return throwable;
    }

    /**
     * 打印栈回溯
     * @param TAG TAG，可选
     * @param context 上下文，不支持忽略
     * @param modeFlag true=FUZZY
     */
    static printBacktrace(TAG: string = "", context: CpuContext, modeFlag: boolean = false): void {
        console.log("========================================  " + TAG + " backtrace strat  ========================================");
        console.log(this.getBacktrace(context, modeFlag));
        console.log("=========================================  " + TAG + " backtrace end  =========================================\r\n");
    }

    /**
     * 从std::string对象中取到str
     * TODO: no test
     * @param strPtr 地址指针
     */
    static getStdStringStr(strPtr: NativePointer): string {
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
    static getJstringStr(strPtr: NativePointer): string {
        return Java.vm.getEnv().getStringUtfChars(strPtr, null).readCString();
    }

    /**
     * 新建一个jstring对象
     * @param str 字符串值
     */
    static newJstring(str: string): NativePointer {
        return Java.vm.getEnv().newStringUtf(str);
    }

    /**
     * 写内容到指定文件（需有权限）
     * @param filename 输出文件的全路径
     * @param contents 要输出的内容
     */
    static writeFile(filename: string = "/data/local/tmp/ooout.txt", contents: string) {
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

    static nop_arm64(addr) {
        Memory.patchCode(ptr(addr), 4, code => {
            const cw = new Arm64Writer(code, {pc: ptr(addr)});
            cw.putNop();
            cw.putNop();
            cw.putNop();
            cw.putNop();
            cw.flush();
        });
    }

    static nop_thumb(addr) {
        Memory.patchCode(ptr(addr), 4, code => {
            const cw = new ThumbWriter(code, {pc: ptr(addr)});
            cw.putNop();
            cw.putNop();
            cw.flush();
        });
    }
}
