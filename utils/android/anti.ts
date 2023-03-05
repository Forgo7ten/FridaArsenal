import Wrapper = Java.Wrapper;
import {common} from "../common";
import Flog = common.Flog;

export class _Anti {

    /**
     * 对栈进行hook，并过滤栈信息
     */
    static filter_stack() {
        const TAG = "filter_stack"

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
     * 过滤SystemProperty中的代理检测
     * TODO: 可拓展为针对特定的属性返回特定的值 的类(通过Map)
     */
    static filterSystemProxy() {
        const TAG = "filterSystemProxy";
        Java.perform(function () {
            let System = Java.use("java.lang.System")
            // 过滤代理
            let nullProperties = ["http.proxyHost", "http.proxyPort", "https.proxyHost", "https.proxyPort"]

            function hitRule(propertyStr: string) {
                nullProperties.forEach((nullProperty) => {
                    if (propertyStr.indexOf(nullProperty) >= 0) {
                        Flog.d(TAG, "Hit->${propertyStr}")
                        return true;
                    }
                })
                return false;
            }

            System["getProperty"].overload('java.lang.String').implementation = function (str: string) {
                if (hitRule(str)) {
                    return null
                }
                let ret = this.getProperty(str)
                return ret
            }
            System["getProperty"].overload('java.lang.String', 'java.lang.String').implementation = function (str1: string, str2: string) {
                if (hitRule(str1)) {
                    return null;
                }
                let ret = this.getProperty(str1, str2)
                return ret
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