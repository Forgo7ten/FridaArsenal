Java.perform(function() {
  var Toast = Java.use('android.widget.Toast');
  var currentApplication = Java.use('android.app.ActivityThread').currentApplication(); 
  var context = currentApplication.getApplicationContext();

  Java.scheduleOnMainThread(function() {
    Toast.makeText(context, "Hello World", Toast.LENGTH_LONG.value).show();
  })
})