function getContext(){
    Java.perform(function(){
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
        console.log(currentApplication);
        var context = currentApplication.getApplicationContext();
        console.log(context);
        var packageName = context.getPackageName();
        console.log(packageName);
        console.log(currentApplication.getPackageName());
    })
}