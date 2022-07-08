Java.perform(function () {
    var Activity = Java.use("android.app.Activity");
    //console.log(Object.getOwnPropertyNames(Activity));
    Activity.startActivity.overload('android.content.Intent').implementation=function(p1){
        console.log("Hooking android.app.Activity.startActivity(p1) successfully,p1="+p1);
        //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        console.log(decodeURIComponent(p1.toUri(256)));
        this.startActivity(p1);
    }
    Activity.startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation=function(p1,p2){
        console.log("Hooking android.app.Activity.startActivity(p1,p2) successfully,p1="+p1+",p2="+p2);
        //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        console.log(decodeURIComponent(p1.toUri(256)));
        this.startActivity(p1,p2);
    }
    Activity.startService.overload('android.content.Intent').implementation=function(p1){
        console.log("Hooking android.app.Activity.startService(p1) successfully,p1="+p1);
        //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        console.log(decodeURIComponent(p1.toUri(256)));
        this.startService(p1);
    }
})