function printStack(name = "") {
    Java.perform(function () {
        var throwable = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        console.log("=============================" + name + " Stack strat=======================");
        console.log(throwable);
        console.log("=============================" + name + " Stack end=======================\r\n");
    });
}

function printStack1(name = "") {
    Java.perform(function () {
        var exception = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        console.log("=============================" + name + " Stack strat=======================");
        console.log(exception);
        console.log("=============================" + name + " Stack end=======================\r\n");
    });
}

function printStack2(name = "") {
    Java.perform(function () {
        var Exception = Java.use("java.lang.Exception");
        var ins = Exception.$new("Exception");
        var straces = ins.getStackTrace();
        if (straces != undefined && straces != null) {
            var strace = straces.toString();
            var replaceStr = strace.replace(/,/g, "\n");
            console.log("=============================" + name + " Stack strat=======================");
            console.log(replaceStr);
            console.log("=============================" + name + " Stack end=======================\r\n");
            Exception.$dispose();
        }
    });
}
