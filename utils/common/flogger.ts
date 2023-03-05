import Wrapper = Java.Wrapper;

export class _Flog {
    static debugFlag: boolean = true;
    static readonly TAG: string = "FridaLog"

    static d(msg: string): void;

    static d(tag: string, msg: string): void;

    static d(tag_or_msg: any, msg?: string): void {
        if (this.debugFlag) {
            if (msg) {
                _Flog._log(console.log, 'DEBUG', tag_or_msg, msg);
            } else {
                _Flog._log(console.log, 'DEBUG', _Flog.TAG, tag_or_msg);
            }
        }
    }

    static i(msg: string): void;

    static i(tag: string, msg: string): void;

    static i(tag_or_msg: any, msg?: string): void {
        if (msg) {
            _Flog._log(console.log, 'INFO', tag_or_msg, msg);
        } else {
            _Flog._log(console.log, 'INFO', _Flog.TAG, tag_or_msg);
        }
    }

    static w(msg: string): void;

    static w(tag: string, msg: string): void;

    static w(tag_or_msg: any, msg?: string): void {
        if (msg) {
            _Flog._log(console.warn, 'WARN', tag_or_msg, msg);
        } else {
            _Flog._log(console.warn, 'WARN', _Flog.TAG, tag_or_msg);
        }
    }

    static e(msg: string): void;

    static e(tag: string, msg: string): void;

    static e(tag_or_msg: any, msg?: string): void {
        if (msg) {
            _Flog._log(console.error, 'ERROR', tag_or_msg, msg);
        } else {
            _Flog._log(console.error, 'ERROR', _Flog.TAG, tag_or_msg);
        }
    }

    static _log(logfunc: (message?: any, ...optionalParams: any[]) => void, leval: string, tag: string, msg: string) {
        try {
            let threadName = "";
            if (Java.available) {
                Java.perform(() => {
                    const Thread: Wrapper = Java.use('java.lang.Thread');
                    threadName = `[${(<Wrapper>Thread.currentThread()).getName()}]`;
                });
            }
            // logfunc(`[${leval}][${new Date().toLocaleString('zh-CN')}][PID:${Process.id}]${threadName}[${Process.getCurrentThreadId()}][${tag}]: ${msg}`);
            logfunc(`[${leval}][${new Date().toLocaleString('zh-CN')}][${Process.id}]${threadName}[${tag}]: ${msg}`);
        } catch (err) {
            if (err instanceof ReferenceError) {
                logfunc(`[${leval}][${new Date().toLocaleString('zh-CN')}][${tag}]: ${msg}`);
            }
        }

    }

    static send(content: string): void;

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
                tag: _Flog.TAG,
                content: tag_or_msg
            }));
        }
    }
}