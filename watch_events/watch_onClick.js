/**
 * HOOKonClick函数，打印onClick匿名类
 */

var jclazz = null;
var jobj = null;
function getObjClassName(obj) {
    if (!jclazz) {
        var jclazz = Java.use("java.lang.Class");
    }
    if (!jobj) {
        var jobj = Java.use("java.lang.Object");
    }
    return jclazz.getName.call(jobj.getClass.call(obj));
}

function watch(obj, mtdName) {
    var listener_name = getObjClassName(obj);
    var target = Java.use(listener_name);
    if (!target || !mtdName in target) {
        return;
    }
    // send("[WatchEvent] hooking " + mtdName + ": " + listener_name);
    target[mtdName].overloads.forEach(function (overload) {
        overload.implementation = function () {
            //send("[WatchEvent] " + mtdName + ": " + getObjClassName(this));
            console.log("[WatchEvent] " + mtdName + ": " + getObjClassName(this));
            return this[mtdName].apply(this, arguments);
        };
    });
}

function OnClickListener() {
    Java.perform(function () {
        // 以spawn的模式自启动的hook
        // HOOK View.onClick方法，监控
        Java.use("android.view.View").setOnClickListener.implementation = function (listener) {
            if (listener != null) {
                watch(listener, "onClick");
            }
            return this.setOnClickListener(listener);
        };

        // attach模式去附加进程的hook，就是更慢的hook，需要看hook的时机，hook一些已有的东西
        Java.choose("android.view.View$ListenerInfo", {
            onMatch: function (instance) {
                instance = instance.mOnClickListener.value;
                if (instance) {
                    console.log("mOnClickListener name is :" + getObjClassName(instance));
                    watch(instance, "onClick");
                }
            },
            onComplete: function () {},
        });
    });
}

setImmediate(OnClickListener);