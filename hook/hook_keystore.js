/**
 * hook证书密码及导出证书
 */
function hook_KeyStore_load() {
    Java.perform(function () {
        var myArray = new Array(1024);
        var i = 0;
        for (i = 0; i < myArray.length; i++) {
            myArray[i] = 0x0;
        }
        var buffer = Java.array("byte", myArray);

        var StringClass = Java.use("java.lang.String");
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.load.overload("java.security.KeyStore$LoadStoreParameter").implementation = function (password) {
            // 打印调用栈
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            // 打印密码
            console.log("KeyStore[1] called:", password);
            this.load(password);
        };
        KeyStore.load.overload("java.io.InputStream", "[C").implementation = function (certificate, password) {
            // 打印调用栈
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));

            console.log("KeyStore[2] called:", certificate, password ? StringClass.$new(password) : null);
            // 如果证书存在导出证书文件
            if (certificate) {
                var file = Java.use("java.io.File").$new("/sdcard/Download/" + String(certificate) + ".p12");
                var out = Java.use("java.io.FileOutputStream").$new(file);
                var r;
                while ((r = certificate.read(buffer)) > 0) {
                    out.write(buffer, 0, r);
                }
                console.log("save keystore success!");
                out.close();
            }
            this.load(certificate, password);
        };

        console.log("hook_KeyStore_load...");
    });
}

function main() {
    hook_KeyStore_load();
}
setImmediate(main);