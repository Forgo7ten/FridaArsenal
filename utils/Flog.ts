import Wrapper = Java.Wrapper;

/**
 * 日志工具模块
 *
 * 使用示例：
 *   import { Flog } from "./Flog";
 *   Flog.d("Hello world");
 *   Flog.setLogLevel(Flog.LOG_LEVEL_WARN);
 */
export const Flog = (() => {
    // 私有常量
    const TAG = "FridaLog";

    // 日志等级常量
    const LOG_LEVEL_DEBUG = 0;
    const LOG_LEVEL_INFO = 1;
    const LOG_LEVEL_WARN = 2;
    const LOG_LEVEL_ERROR = 3;

    // 内部状态
    let level = LOG_LEVEL_DEBUG;
    // 不使用Java
    let noJavaFlag = false;

    // 内部通用日志函数
    function _log(
        logfunc: (message?: any, ...optionalParams: any[]) => void,
        logLevel: string,
        tag: string,
        msg: string
    ) {
        if (noJavaFlag) {
            logfunc(`[${logLevel}][${new Date().toLocaleString("zh-CN")}][${Process.id}][${tag}]: ${msg}`);
            return;
        }

        try {
            let threadName = "";
            if (Java.available) {
                Java.perform(() => {
                    const Thread: Wrapper = Java.use("java.lang.Thread");
                    threadName = `[${(<Wrapper>Thread.currentThread()).getName()}]`;
                });
            }
            logfunc(`[${logLevel}][${new Date().toLocaleString("zh-CN")}][${Process.id}]${threadName}[${tag}]: ${msg}`);
        } catch {
            logfunc(`[${logLevel}][${new Date().toLocaleString("zh-CN")}][${Process.id}][${tag}]: ${msg}`);
        }
    }


    /**
     * 设置Flag，不调用JavaAPI
     */
    function noJava() {
        noJavaFlag = true;
    }

    /**
     * 设置日志等级
     */
    function setLogLevel(lv: number) {
        switch (lv) {
            case LOG_LEVEL_DEBUG:
            case LOG_LEVEL_INFO:
            case LOG_LEVEL_WARN:
            case LOG_LEVEL_ERROR:
                level = lv;
                break;
            default:
                level = LOG_LEVEL_DEBUG;
                e("Error level!");
                break;
        }
    }

    /**
     * 打印分割线
     */
    function line(tag_or_msg: string, msg?: string) {
        if (msg) {
            i(tag_or_msg, `========================================  ${msg}  ========================================`);
        } else {
            i(`========================================  ${tag_or_msg}  ========================================`);
        }
    }

    /** debug 日志 */
    function d(tag_or_msg: string, msg?: string) {
        if (LOG_LEVEL_DEBUG >= level) {
            if (msg) _log(console.log, "DEBUG", tag_or_msg, msg);
            else _log(console.log, "DEBUG", TAG, tag_or_msg);
        }
    }

    /** info 日志 */
    function i(tag_or_msg: string, msg?: string) {
        if (LOG_LEVEL_INFO >= level) {
            if (msg) _log(console.log, "INFO", tag_or_msg, msg);
            else _log(console.log, "INFO", TAG, tag_or_msg);
        }
    }

    /** warn 日志 */
    function w(tag_or_msg: string, msg?: string) {
        if (LOG_LEVEL_WARN >= level) {
            if (msg) _log(console.warn, "WARN", tag_or_msg, msg);
            else _log(console.warn, "WARN", TAG, tag_or_msg);
        }
    }


    /** error 日志 */
    function e(tag_or_msg: string, msg?: string) {
        if (LOG_LEVEL_ERROR >= level) {
            if (msg) _log(console.error, "ERROR", tag_or_msg, msg);
            else _log(console.error, "ERROR", TAG, tag_or_msg);
        }
    }

    const fridaSend: typeof send = (globalThis as any).send;

    /**
     * 发送日志到 Python
     */
    function send(tag_or_msg: string, content?: string) {
        const tid = Process.getCurrentThreadId();
        const tag = content ? tag_or_msg : TAG;
        const message = content ?? tag_or_msg;
        fridaSend(JSON.stringify({tid, status: "msg", tag, content: message}));
    }

    return {
        /** 日志等级常量 */
        LOG_LEVEL_DEBUG,
        LOG_LEVEL_INFO,
        LOG_LEVEL_WARN,
        LOG_LEVEL_ERROR,

        /** 获取日志Tag（只读） */
        TAG,
        noJava,
        setLogLevel,
        line,
        d,
        i,
        w,
        e,
        send,
    };
})();