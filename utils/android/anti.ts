import Wrapper = Java.Wrapper;
import {common} from "../common";
import Flog = common.Flog;

export class _Anti {

    /**
     * 对栈进行hook，并过滤栈信息
     */
    static filterStack() {
        const TAG = "filterStack"

        // TODO: Xposed用户模块的函数调用栈，未能成功过滤
        /**
         * 过滤栈的判断，当不含有关键字时，返回true
         * @param stack_str java栈元素字符串
         * @returns true则通过过滤
         */
        function filter_key(stack_str: string): boolean {
            let filter_arr = ["lsp", "xposed", "java.lang.reflect.Method.invoke(Native Method)"];
            for (let filter_str of filter_arr) {
                if (stack_str.toLowerCase().indexOf(filter_str.toLowerCase()) >= 0) {
                    return false;
                }
            }
            return true;
        }

        function faked_stack(stacks: Wrapper[]): Wrapper[] {
            let newStacks: Wrapper[] = []
            for (let i = 0; i < stacks.length; i++) {
                let stack = stacks[i];
                let stack_str = stack.toString();
                // 过滤栈中的一些字眼
                if (!filter_key(stack_str)) continue;
                // 过滤Frida的情况
                if (newStacks.length > 0 && stack_str.indexOf(newStacks[newStacks.length - 1].toString().split('(')[0] + "(Native Method)") >= 0) continue;
                newStacks.push(stack);
            }
            return newStacks;
        }

        Java.perform(function () {
            let Throwable = Java.use("java.lang.Throwable");
            let Thread = Java.use("java.lang.Thread");
            let VMStack = Java.use("dalvik.system.VMStack")
            let StackTraceElement = Java.use("java.lang.StackTraceElement");

            Throwable["getOurStackTrace"].implementation = function () {
                Flog.d(TAG, "Throwable.getOurStackTrace()")
                let stacks = this.getOurStackTrace();
                let newStacks = faked_stack(stacks);
                return newStacks;
            };
            Thread["getStackTrace"].implementation = function () {
                Flog.d(TAG, "Thread.getStackTrace()")
                let stacks = this.getStackTrace();
                let newStacks = faked_stack(stacks);
                return newStacks;
            };
            VMStack["getThreadStackTrace"].implementation = function (thread: Wrapper) {
                Flog.d(TAG, "VMStack.getThreadStackTrace(" + thread + ")")
                let stacks = this.getThreadStackTrace(thread);
                let newStacks = faked_stack(stacks);
                return newStacks;
            };
        })
        Flog.d(TAG, "Filter stack")
    }

    /**
     * 存放修改后的SystemProp
     * @protected
     */
    protected static propsMap = new Map<string, any>([
        // 代理检测
        ["http.proxyHost", null],
        ["http.proxyPort", null],
        ["https.proxyHost", null],
        ["https.proxyPort", null],
    ]);

    protected static __props_watch_FLAG = false;
    protected static __props_filter_FLAG = false;

    /**
     * 过滤并替换系统props
     * @param key 要过滤的key
     * @param value key对应的值
     */
    static filterProps(key: string = null, value: any = null): void {
        if (key !== null) this.propsMap.set(key, value);
        this.__props_filter_FLAG = true;
        this.hookProps();
    }

    /**
     * 监控系统props读取
     */
    static watchProps(): void {
        this.__props_watch_FLAG = true;
        this.hookProps();
    }

    /**
     * 对读取系统prop相关方法进行hook
     */
    private static hookProps() {
        const TAG = "watchProps";
        Java.perform(function () {
            let Properties = Java.use("java.util.Properties");
            Properties["getProperty"].overload('java.lang.String').implementation = function (key) {
                let value = this["getProperty"](key);
                if (_Anti.__props_watch_FLAG) {
                    Flog.d(TAG, `Properties.getProperty(${key})=${value}`);
                }
                if (_Anti.__props_filter_FLAG) {
                    const filterValue = _Anti.propsMap.get(key);
                    if (filterValue !== undefined) {
                        value = filterValue;
                        if (_Anti.__props_watch_FLAG) Flog.d(TAG, `modified! Properties.getProperty(${key})=${value}`);
                    }
                }
                return value;
            }
            let SystemProperties = Java.use("android.os.SystemProperties");
            SystemProperties["native_get"].overload('java.lang.String').implementation = function (key) {
                let value = this["native_get"](key);
                if (_Anti.__props_watch_FLAG) {
                    Flog.d(TAG, `SystemProperties.get(${key})=${value}`);
                }
                if (_Anti.__props_filter_FLAG) {
                    const filterValue = _Anti.propsMap.get(key);
                    if (filterValue !== undefined) {
                        value = filterValue;
                        if (_Anti.__props_watch_FLAG) Flog.d(TAG, `modified! SystemProperties.get(${key})=${value}`);
                    }
                }
                return value;
            }
            SystemProperties["native_get"].overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
                let value = this["native_get"](key, def);
                if (_Anti.__props_watch_FLAG) {
                    Flog.d(TAG, `SystemProperties.get(${key},${def})=${value}`);
                }
                if (_Anti.__props_filter_FLAG) {
                    const filterValue = _Anti.propsMap.get(key);
                    if (filterValue !== undefined) {
                        value = filterValue;
                        if (_Anti.__props_watch_FLAG) Flog.d(TAG, `modified! SystemProperties.get(${key},${def})=${value}`);
                    }
                }
                return value;
            }
            SystemProperties["native_get_int"].overload('java.lang.String', 'int').implementation = function (key, def) {
                let value = this["native_get_int"](key, def);
                if (_Anti.__props_watch_FLAG) {
                    Flog.d(TAG, `SystemProperties.getInt(${key},${def})=${value}`);
                }
                if (_Anti.__props_filter_FLAG) {
                    const filterValue = _Anti.propsMap.get(key);
                    if (filterValue !== undefined) {
                        value = filterValue;
                        if (_Anti.__props_watch_FLAG) Flog.d(TAG, `modified! SystemProperties.getInt(${key},${def})=${value}`);
                    }
                }
                return value;
            }
            SystemProperties["native_get_long"].overload('java.lang.String', 'long').implementation = function (key, def) {
                let value = this["native_get_long"](key, def);
                if (_Anti.__props_watch_FLAG) {
                    Flog.d(TAG, `SystemProperties.getLong(${key},${def})=${value}`);
                }
                if (_Anti.__props_filter_FLAG) {
                    const filterValue = _Anti.propsMap.get(key);
                    if (filterValue !== undefined) {
                        value = filterValue;
                        if (_Anti.__props_watch_FLAG) Flog.d(TAG, `modified! SystemProperties.getLong(${key},${def})=${value}`);
                    }
                }
                return value;
            }
            SystemProperties["native_get_boolean"].overload('java.lang.String', 'boolean').implementation = function (key, def) {
                let value = this["native_get_boolean"](key, def);
                if (_Anti.__props_watch_FLAG) {
                    Flog.d(TAG, `SystemProperties.getBoolean(${key},${def})=${value}`);
                }
                if (_Anti.__props_filter_FLAG) {
                    const filterValue = _Anti.propsMap.get(key);
                    if (filterValue !== undefined) {
                        value = filterValue;
                        if (_Anti.__props_watch_FLAG) Flog.d(TAG, `modified! SystemProperties.getBoolean(${key},${def})=${value}`);
                    }
                }
                return value;
            }
        })
    }

    static antiVpn() {
        const TAG = "antiVpn"
        Java.perform(function () {
            let NetworkInterface = Java.use("java.net.NetworkInterface")
            let NetworkInfo = Java.use("android.net.NetworkInfo")
            let NetworkCapabilities = Java.use("android.net.NetworkCapabilities")
            NetworkInterface.getNetworkInterfaces.implementation = function () {
                Flog.d(TAG, "NetworkInterface.getNetworkInterfaces()")
                let ret = this.getNetworkInterfaces()
                return null;
            }
            NetworkCapabilities.isConnected.implementation = function () {
                Flog.d(TAG, "NetworkCapabilities.isConnected()")
                return false
            }

            NetworkInterface.getName.implementation = function () {
                Flog.d(TAG, "NetworkInterface.getName()")
                return ""
            }

            NetworkInfo.hasTransport.implementation = function () {
                Flog.d(TAG, "NetworkInfo.hasTransport()")
                return false
            }
        })
    }
}