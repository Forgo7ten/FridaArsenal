function getContext() {
    Java.perform(function () {
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
        var context = currentApplication.getApplicationContext();
        console.log(context);
        return context;
        /* var packageName = context.getPackageName();
        console.log(packageName);
        console.log(currentApplication.getPackageName()); */
    })
}