import {common} from "../common";
import {_Helper} from "./helper";
import Flog = common.Flog;
import Wrapper = Java.Wrapper;
import Method = Java.Method;

export class _WatchViews {

    static __Toast_clazz: Wrapper

    /**
     * 监视toast
     */
    static watchToast(): void {
        Java.perform(function () {
            let Toast = Java.use("android.widget.Toast");
            Toast.show.implementation = function () {
                _Helper.printStack("SHOW Toast");
                return this.show();
            };
        });
    }

    static watchIntent(): void {
        const TAG = "watchIntent"
        Java.perform(function () {
            let Activity = Java.use("android.app.Activity");
            Activity.startActivity.overload('android.content.Intent').implementation = function (intent: Wrapper) {
                Flog.i(TAG, `Hooking android.app.Activity.startActivity(intent) successfully,intent=${intent},decodeIntent=${decodeURIComponent(intent.toUri(256))}`);
                //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
                this.startActivity(intent);
            }
            Activity.startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function (intent: Wrapper, bundle: Wrapper) {
                Flog.i(TAG, `Hooking android.app.Activity.startActivity(intent,bundle) successfully,intent=${intent},bundle=${bundle},decodeIntent=${decodeURIComponent(intent.toUri(256))}`);
                this.startActivity(intent, bundle);
            }
            Activity.startService.overload('android.content.Intent').implementation = function (intent: Wrapper) {
                Flog.i(TAG, `Hooking android.app.Activity.startService(intent) successfully,intent=${intent},decodeIntent=${decodeURIComponent(intent.toUri(256))}`);
                this.startService(intent);
            }
        })
    }

    static watchOnclick(): void {
        const TAG = "watchOnclick"

        function watch(obj: Wrapper, methodName: string) {
            let listener_name = _Helper.getObjClassName(obj);
            let target: Wrapper = Java.use(listener_name);
            if (!target || !(methodName in target)) {
                return;
            }
            target[methodName].overloads.forEach(function (overload: Method) {
                overload.implementation = function () {
                    Flog.i(TAG, `${methodName}: ${_Helper.getObjClassName(this)}`);
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
                        Flog.d(TAG, `mOnClickListener name is:${_Helper.getObjClassName(instance)}`);
                        watch(instance, "onClick");
                    }
                },
                onComplete: function () {
                }
            });
        });
    }
}