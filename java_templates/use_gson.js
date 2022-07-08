Java.openClassFile("xxx.dex").load();

// 示例
Java.openClassFile("/data/local/tmp/r0gson.dex").load();
const gson = Java.use('com.r0ysue.gson.Gson');
gson.$new().toJson( object );