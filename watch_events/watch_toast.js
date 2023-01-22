function hook_toast() {
    Java.perform(function () {
        var Toast = Java.use("android.widget.Toast");
        Toast.show.implementation = function () {
            printStack("SHOW Toast");
            return this.show();
        };
    });
}

setImmediate(hook_toast);

function printStack(name) {
    Java.perform(function () {
        var throwable = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        console.log("=============================" + name + " Stack strat=======================");
        console.log(throwable);
        console.log("=============================" + name + " Stack end=======================\r\n");
    });
}