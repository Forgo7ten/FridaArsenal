import Wrapper = Java.Wrapper;

/**
 * @class 日志工具类
 */
export class Flog {
    /** @readonly DEBUG等级日志 */
    static LOG_LEVEL_DEBUG: number = 0;
    /** @readonly INFO等级日志 */
    static LOG_LEVEL_INFO: number = 1;
    /** @readonly WARN等级日志 */
    static LOG_LEVEL_WARN: number = 2;
    /** @readonly ERROR等级日志 */
    static LOG_LEVEL_ERROR: number = 3;
    /** @private */
    static level: number = this.LOG_LEVEL_DEBUG;

    /**
     * 设置日志等级，低于日志等级的日志不会打印
     * @param level 日志等级
     */
    static setLogLevel(level: number) {
        switch (level) {
            case 0:
            case 1:
            case 2:
            case 3:
                this.level = level;
                break;
            default:
                this.level = this.LOG_LEVEL_DEBUG;
                this.e("Error level!")
                break;
        }
    }

    static readonly TAG: string = "FridaLog"

    static line(msg: string): void;
    static line(tag: string, msg: string): void;

    static line(tag_or_msg: any, msg?: string): void {
        if (msg) {
            this.i(tag_or_msg, `========================================  ${msg}  ========================================`)
        } else {
            this.i(`========================================  ${tag_or_msg}  ========================================`)
        }
    }

    /**
     * debug等级日志
     * @param msg 要打印的日志
     */
    static d(msg: string): void;

    /**
     * debug等级日志
     * @param tag 要打印的日志
     * @param msg 日志所属TAG
     */
    static d(tag: string, msg: string): void;

    static d(tag_or_msg: any, msg?: string): void {
        if (this.LOG_LEVEL_DEBUG >= this.level) {
            if (msg) {
                Flog._log(console.log, 'DEBUG', tag_or_msg, msg);
            } else {
                Flog._log(console.log, 'DEBUG', Flog.TAG, tag_or_msg);
            }
        }
    }

    /**
     * info等级日志
     * @param msg 要打印的日志
     */
    static i(msg: string): void;

    /**
     * info等级日志
     * @param tag 日志所属TAG
     * @param msg 要打印的日志
     */
    static i(tag: string, msg: string): void;

    static i(tag_or_msg: any, msg?: string): void {
        if (this.LOG_LEVEL_INFO >= this.level) {
            if (msg) {
                Flog._log(console.log, 'INFO', tag_or_msg, msg);
            } else {
                Flog._log(console.log, 'INFO', Flog.TAG, tag_or_msg);
            }
        }
    }

    /**
     * warn等级日志
     * @param msg 要打印的日志
     */
    static w(msg: string): void;
    /**
     * warn等级日志
     * @param tag 日志所属TAG
     * @param msg 要打印的日志
     */
    static w(tag: string, msg: string): void;

    static w(tag_or_msg: any, msg?: string): void {
        if (this.LOG_LEVEL_WARN >= this.level) {
            if (msg) {
                Flog._log(console.warn, 'WARN', tag_or_msg, msg);
            } else {
                Flog._log(console.warn, 'WARN', Flog.TAG, tag_or_msg);
            }
        }
    }

    /**
     * error等级日志
     * @param msg 要打印的日志
     */
    static e(msg: string): void;
    /**
     * error等级日志
     * @param tag 日志所属TAG
     * @param msg 要打印的日志
     */
    static e(tag: string, msg: string): void;

    static e(tag_or_msg: any, msg?: string): void {
        if (this.LOG_LEVEL_ERROR >= this.level) {
            if (msg) {
                Flog._log(console.error, 'ERROR', tag_or_msg, msg);
            } else {
                Flog._log(console.error, 'ERROR', Flog.TAG, tag_or_msg);
            }
        }
    }

    static _log(logfunc: (message?: any, ...optionalParams: any[]) => void, level: string, tag: string, msg: string) {
        try {
            let threadName = "";
            if (Java.available) {
                Java.perform(() => {
                    const Thread: Wrapper = Java.use('java.lang.Thread');
                    threadName = `[${(<Wrapper>Thread.currentThread()).getName()}]`;
                });
            }
            // logfunc(`[${level}][${new Date().toLocaleString('zh-CN')}][PID:${Process.id}]${threadName}[${Process.getCurrentThreadId()}][${tag}]: ${msg}`);
            logfunc(`[${level}][${new Date().toLocaleString('zh-CN')}][${Process.id}]${threadName}[${tag}]: ${msg}`);
        } catch (err) {
            if (err instanceof ReferenceError) {
                logfunc(`[${level}][${new Date().toLocaleString('zh-CN')}][${tag}]: ${msg}`);
            }
        }

    }

    /**
     * send消息到python
     * @param content 要打印的日志
     */
    static send(content: string): void;
    /**
     * send消息到python
     * @param tag 日志所属TAG
     * @param content 要打印的日志
     */
    static send(tag: string, content: string): void;

    static send(tag_or_msg: any, content?: string): void {
        let tid = Process.getCurrentThreadId();
        if (content) {
            send(JSON.stringify({
                tid: tid,
                status: 'msg',
                tag: tag_or_msg,
                content: content
            }));
        } else {
            send(JSON.stringify({
                tid: tid,
                status: 'msg',
                tag: Flog.TAG,
                content: tag_or_msg
            }));
        }
    }
}