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
    let _noJava = false;
    // 不打印时间
    let _noDateFmt = false;

    // 延迟打印
    class DelayedLogger {
        private queue: string[] = [];
        private maxQueueSize: number = 9999;
        private timerId: any = null;
        private flushInterval: number = 0;
        private enabled: boolean = false;

        push(logEntry: string) {
            this.queue.push(logEntry);
            if (this.queue.length >= this.maxQueueSize) {
                this.flush();
            }
        }

        flush() {
            if (this.queue.length > 0) {
                // delay之后丢失level（无所谓）
                console.log(this.queue.join("\n"));
                this.queue = [];
            }
        }

        isEnabled() {
            return this.enabled;
        }

        enable(interval: number = 50) {
            if (interval <= 0) {
                this.disable();
                return;
            }

            if (this.enabled && this.flushInterval !== interval) {
                this.disable();
            }
            if (this.enabled) return;

            this.enabled = true;
            this.flushInterval = interval;
            this.timerId = setInterval(() => this.flush(), this.flushInterval);
        }

        disable() {
            if (!this.enabled) return;

            this.enabled = false;
            if (this.timerId) {
                clearInterval(this.timerId);
                this.timerId = null;
            }
            this.flush(); // 立即刷新剩余日志
        }
    }

    const delayedLogger = new DelayedLogger();

    /**
     * 启用延迟打印 与noJava配合
     * @param interval 刷新间隔(ms)，默认50ms，设置为0或负数则禁用
     */
    function enableDelayedLogging(interval?: number) {
        delayedLogger.enable(interval);
    }

    /**
     * 禁用延迟打印并立即刷新所有缓冲的日志
     */
    function disableDelayedLogging() {
        delayedLogger.disable();
    }

    /**
     * 手动刷新延迟日志队列
     */
    function flush() {
        delayedLogger.flush();
    }

    function formatLogMessage(logLevel: string, tag: string, msg: string): string {
        let logStr = `[${logLevel}]${_noDateFmt ? "" : `[${new Date().toLocaleString("zh-CN")}]`}[${Process.id}]`;
        if (!_noJava) {
            try {
                if (Java.available) {
                    Java.perform(() => {
                        const Thread: Wrapper = Java.use("java.lang.Thread");
                        let threadName = `[${(<Wrapper>Thread.currentThread()).getName()}]`;
                        logStr += threadName
                    });
                }
            } catch {
            }
        }
        logStr += `[${tag}]: ${msg}`;
        return logStr;
    }

    // 内部通用日志函数
    function _log(
        logfunc: (message?: any, ...optionalParams: any[]) => void,
        logLevel: string,
        tag: string,
        msg: string
    ) {
        const logMessage = formatLogMessage(logLevel, tag, msg);
        if (delayedLogger.isEnabled()) {
            delayedLogger.push(logMessage);
            return;
        }

        logfunc(logMessage);
    }


    /**
     * 设置Flag，不调用JavaAPI
     */
    function noJava() {
        _noJava = true;
    }

    /**
     * 不打印时间
     */
    function noDateFmt() {
        _noDateFmt = true;
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
                e("Invalid log level! Using DEBUG as default.");
                break;
        }
    }

    /**
     * 可配置的选项
     * @param options 选项{ level?: number; noJava?: boolean; noDateFmt?: boolean; }
     */
    function setOptions(options?: { level?: number; noJava?: boolean; noDateFmt?: boolean; }) {
        if (options) {
            if (undefined !== options.level) {
                setLogLevel(options.level);
            }
            if (undefined !== options.noJava) {
                _noJava = options.noJava;
            }
            if (undefined !== options.noDateFmt) {
                _noDateFmt = options.noDateFmt;
            }
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
        noDateFmt,
        setLogLevel,
        setOptions,
        enableDelayedLogging,
        disableDelayedLogging,
        flush,
        line,
        d,
        i,
        w,
        e,
        send,
    };
})();