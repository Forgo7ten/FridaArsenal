import {Flog} from "../Flog";
import {_AHelperCore} from "./_AHelper.core";
import {_AHelperHook} from "./_AHelper.hook";
import Wrapper = Java.Wrapper;

const {printStack, getClsNameFromObj} = _AHelperCore
const {hookMethodAllOverloads} = _AHelperHook

export const _AHelperWatch = (() => {

    /**
     * watch android.util.log
     * @param printStackFlag
     */
    function watch_logcat(printStackFlag: boolean = false): void {
        ["v", "d", "i", "w", "e", "wtf"].forEach(method_name => hookMethodAllOverloads("android.util.Log", method_name, printStackFlag));
    }

    /**
     * 监听 Toast.show()方法
     */
    function watchToast(): void {
        Java.perform(function () {
            let Toast = Java.use("android.widget.Toast");
            Toast.show.implementation = function () {
                let text = this.mText.value ? this.mText.value.toString() : "";
                printStack("SHOW Toast: " + text);
                return this.show();
            };
        });
    }

    /**
     * 监听弹窗
     */
    function watchDialog(): void {
        let Dialog = Java.use("android.app.Dialog");
        Dialog["show"].implementation = function () {
            Flog.i(`${this} Dialog.show() is called`);
            printStack(`${this} Dialog.show()`)
            this["show"]();
        }
    }

    function watchOnclick(): void {
        const TAG = "watchOnclick"

        function watch(obj: Wrapper, methodName: string) {
            let listener_name = getClsNameFromObj(obj);
            let target: Wrapper = Java.use(listener_name);
            if (!target || !(methodName in target)) {
                return;
            }
            target[methodName].overloads.forEach(function (overload: Java.Method) {
                overload.implementation = function () {
                    Flog.i(TAG, `${methodName}: ${getClsNameFromObj(this)}`);
                    return this[methodName].apply(this, arguments);
                };
            });
        }

        Java.perform(function () {
            // 以spawn的模式自启动的hook
            // HOOK View.onClick方法，监控
            Java.use("android.view.View").setOnClickListener.implementation = function (view: Wrapper) {
                if (view != null) {
                    watch(view, "onClick");
                }
                return this.setOnClickListener(view);
            };

            // attach模式去附加进程的hook，就是更慢的hook，需要看hook的时机，hook一些已有的东西
            Java.choose("android.view.View$ListenerInfo", {
                onMatch: function (instance) {
                    instance = instance.mOnClickListener.value;
                    if (instance) {
                        Flog.d(TAG, `mOnClickListener name is:${getClsNameFromObj(instance)}`);
                        watch(instance, "onClick");
                    }
                },
                onComplete: function () {
                }
            });
        });
    }

    return {
        watch_logcat,
        watchToast,
        watchDialog,
        watchOnclick,
    };
})()