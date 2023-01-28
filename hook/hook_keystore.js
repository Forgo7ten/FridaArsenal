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

/**
 * [未测试] dump客户端证书，并保存为p12的格式，证书密码为Forgo7ten
 */
function hook_keystore() {
    var password = 'Forgo7ten';

    function getNowTime() {
        function dateFormat(fmt, date) {
            let ret;
            const opt = { "Y+": date.getFullYear().toString(), "m+": (date.getMonth() + 1).toString(), "d+": date.getDate().toString(), "H+": date.getHours().toString(), "M+": date.getMinutes().toString(), "S+": date.getSeconds().toString() };
            for (let k in opt) {
                ret = new RegExp("(" + k + ")").exec(fmt);
                if (ret) {
                    fmt = fmt.replace(ret[1], (ret[1].length == 1) ? (opt[k]) : (opt[k].padStart(ret[1].length, "0")))
                };
            };
            return fmt;
        }
        function random(min, max) {
            return Math.floor(Math.random() * (max - min)) + min;
        }
        return dateFormat("YYYY_mm_dd_HH_MM_SS", new Date()) + "_" + random(1, 100);
    }
    Java.perform(function () {
        function storeP12(privateKey, certificate, saveP12Path, p12Password) {
            var X509Certificate = Java.use("java.security.cert.X509Certificate")
            var p7X509 = Java.cast(certificate, X509Certificate);
            var chain = Java.array("java.security.cert.X509Certificate", [p7X509])
            var ks = Java.use("java.security.KeyStore").getInstance("PKCS12", "BC");
            ks.load(null, null);
            ks.setKeyEntry("client", privateKey, Java.use('java.lang.String').$new(p12Password).toCharArray(), chain);
            try {
                var out = Java.use("java.io.FileOutputStream").$new(saveP12Path);
                ks.store(out, Java.use('java.lang.String').$new(p12Password).toCharArray())
            } catch (exp) {
                console.log(exp)
            }
        }
        Java.use("java.security.KeyStore$PrivateKeyEntry").getPrivateKey.implementation = function () {
            var packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
            var savePath = '/sdcard/Download/' + packageName;

            var result = this.getPrivateKey();
            var fileName = savePath + getNowTime() + '.p12'
            storeP12(this.getPrivateKey(), this.getCertificate(), fileName, password);
            console.log("dump ClinetCertificate=>", fileName, "pwd:" + password);
            return result;
        }
        Java.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function () {
            var packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
            var savePath = '/sdcard/Download/' + packageName;
            var result = this.getCertificateChain()
            var fileName = savePath + getNowTime() + '.p12'
            storeP12(this.getPrivateKey(), this.getCertificate(), fileName, password);
            console.log("dump ClinetCertificate=>", fileName, "pwd:" + password);
            return result;
        }
    });
}

function main() {
    hook_KeyStore_load();
}
setImmediate(main);