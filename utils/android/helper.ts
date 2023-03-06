import {common} from "../common";
import Wrapper = Java.Wrapper;
import Flog = common.Flog;

export class _Helper {
    private static __jclazz: Wrapper;
    private static __jobj: Wrapper;

    /**
     * 检查类名，过滤系统类和基本类型。返回false表示命中，需要过滤掉
     * @param name 类名
     * @returns boolean
     */
    static checkClass(name: string): boolean {
        return !(name.indexOf(".") < 0
            || name.startsWith("[")
            || name.startsWith("android")
            || name.startsWith("dalvik")
            || name.startsWith("kotlin")
            || name.startsWith("java")
            || name.startsWith("sun.")
            || name.startsWith("org.")
            || name.startsWith("com.android")
            || name.startsWith("com.google")
            || name.startsWith("libcore.")
            || name.startsWith("de.robv.android.xposed.")
        );
    }

    /**
     * 通过对象，拿到对象的全类名
     * @param {Wrapper} obj 未知对象
     * @returns 对象的全类名
     */
    static getObjClassName(obj: Wrapper): string {
        _Helper.__jclazz = _Helper.__jclazz || Java.use("java.lang.Class");
        _Helper.__jobj = _Helper.__jobj || Java.use("java.lang.Object");
        return _Helper.__jclazz.getName.call(_Helper.__jobj.getClass.call(obj));
    }


    /**
     * Java.cast java对象
     * @param jobj java对象
     * @param cls 认为的该对象可能的类名或类，可省略
     * @returns 强转之后的
     */
    static getWrapper(jobj: Wrapper, cls: Wrapper | string | null = null): Wrapper | null {
        if (jobj == null) {
            return null;
        }
        try {
            cls = cls || jobj.$className;
            if (typeof cls === "string") {
                return Java.cast(jobj, Java.use(cls));
            } else {
                return Java.cast(jobj, cls);
            }
        } catch (error) {
            Flog.e(`ERROR:${error}`)
        }
        return null;
    }


    /**
     * 获得App Context
     */
    static getContext() {
        let context = null;
        Java.perform(function () {
            let currentApplication = Java.use("android.app.ActivityThread").currentApplication();
            context = Java.retain(currentApplication.getApplicationContext());
            /*
            let packageName = context.getPackageName();
            console.log(packageName);
            console.log(currentApplication.getPackageName());
            */
        })
        return context;
    }


    /**
     * 通过反射来获取java对象 成员的值
     * @param {Wrapper} object java对象
     * @param {string} fieldName 字段名
     * @returns 对象成员的值或null
     */
    static getFieldValue(object: Wrapper, fieldName: string): Wrapper | null {
        let field = object.class.getDeclaredField(fieldName);
        field.setAccessible(true)
        let fieldValue = field.get(object)
        if (null === fieldValue) {
            return null;
        }
        return this.getWrapper(fieldValue)
    }


    /**
     * FixMe: 未测试
     * dump客户端证书，并保存为p12的格式，证书密码为Forgo7ten
     */
    static hook_keystore() {
        const TAG = "hook_keystore"
        let password = 'Forgo7ten';

        function getNowTime() {
            function dateFormat(fmt: string, date: Date) {
                let ret;
                const opt: { [key: string]: string } = {
                    "Y+": date.getFullYear().toString(),
                    "m+": (date.getMonth() + 1).toString(),
                    "d+": date.getDate().toString(),
                    "H+": date.getHours().toString(),
                    "M+": date.getMinutes().toString(),
                    "S+": date.getSeconds().toString()
                };
                for (let k in opt) {
                    ret = new RegExp("(" + k + ")").exec(fmt);
                    if (ret) {
                        fmt = fmt.replace(ret[1], (ret[1].length === 1) ? (opt[k]) : (opt[k].padStart(ret[1].length, "0")))
                    }

                }

                return fmt;
            }

            function random(min: number, max: number) {
                return Math.floor(Math.random() * (max - min)) + min;
            }

            return dateFormat("YYYY_mm_dd_HH_MM_SS", new Date()) + "_" + random(1, 100);
        }

        Java.perform(function () {
            function storeP12(privateKey: Wrapper, certificate: Wrapper, saveP12Path: string, p12Password: string) {
                let X509Certificate = Java.use("java.security.cert.X509Certificate")
                let p7X509 = Java.cast(certificate, X509Certificate);
                let chain = Java.array("java.security.cert.X509Certificate", [p7X509])
                let ks = Java.use("java.security.KeyStore").getInstance("PKCS12", "BC");
                ks.load(null, null);
                ks.setKeyEntry("client", privateKey, Java.use('java.lang.String').$new(p12Password).toCharArray(), chain);
                try {
                    let out = Java.use("java.io.FileOutputStream").$new(saveP12Path);
                    ks.store(out, Java.use('java.lang.String').$new(p12Password).toCharArray())
                } catch (error) {
                    Flog.e(TAG, `storeP12 error:${error}`)
                }
            }

            Java.use("java.security.KeyStore$PrivateKeyEntry").getPrivateKey.implementation = function () {
                let packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
                let savePath = '/sdcard/Download/' + packageName;

                let result = this.getPrivateKey();
                let fileName = savePath + getNowTime() + '.p12'
                storeP12(this.getPrivateKey(), this.getCertificate(), fileName, password);
                Flog.i(TAG, `dump ClinetCertificate => ${fileName} pwd: ${password}`);
                return result;
            }
            Java.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function () {
                let packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
                let savePath = '/sdcard/Download/' + packageName;
                let result = this.getCertificateChain()
                let fileName = savePath + getNowTime() + '.p12'
                storeP12(this.getPrivateKey(), this.getCertificate(), fileName, password);
                Flog.i(TAG, `dump ClinetCertificate => ${fileName} pwd: ${password}`);

                return result;
            }
        });
    }


    /**
     * 获得调用栈字符串
     */
    static getStack(): string {
        let throwable = "";
        Java.perform(function () {
            throwable = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        });
        return throwable;
    }

    /**
     * 打印调用栈
     * @param TAG TAG，可选
     */
    static printStack(TAG: string = ""): void {
        console.log("========================================  " + TAG + " Stack strat  ========================================");
        console.log(this.getStack());
        console.log("========================================  " + TAG + " Stack end  ========================================\r\n");
    }

    private static __gson_obj: Wrapper | null = null;

    /**
     * 将对象转成json字符串
     * @param {object} obj 要转成json的对象
     * @returns json字符串
     */
    static toGson(obj: Wrapper): string | undefined {
        try {
            if (this.__gson_obj == null) {
                Java.openClassFile("/data/local/tmp/fgson.dex").load();
                this.__gson_obj = Java.use('com.forgo7ten.gson.Gson');
            }
            return this.__gson_obj.$new().toJson(obj);
        } catch (error) {
            // md5sum fgson.dex: a7c58b60a7339e6a1207d5207c847bd5  fgson.dex
            Flog.e("toGson", `Please install the jar into the device first. ${error}`)
        }
    }

    /**
     * FixMe: writeS8 未测试
     * 十六进制打印数组
     * @param {*} array 数组
     * @param {*} off 偏移
     * @param {*} len 长度
     */
    static jhexdump(array: Wrapper[], off: number, len: number) {
        off = off || 0;
        len = len || 0;
        len = len == 0 ? array.length : len;
        let ptr = Memory.alloc(len);
        for (let i = 0; i < len; ++i) {
            // @ts-ignore
            Memory.writeS8(ptr.add(i), array[i]);
        }
        //console.log(hexdump(ptr, { offset: off, length: len, header: false, ansi: false }));
        console.log(hexdump(ptr, {offset: off == 0 ? 0 : off, length: len, header: false, ansi: false}));
    }
}