import {common} from "../common";
import Wrapper = Java.Wrapper;
import Flog = common.Flog;

export class _CastHelper {
    static readonly TAG = "CastHelper"
    static String_clazz: Wrapper = null;
    static Base64_clazz: Wrapper = null;
    static ByteString_clazz: Wrapper = null;

    static getStringClz(): Wrapper {
        if (!this.String_clazz) this.String_clazz = Java.use("java.lang.String");
        return this.String_clazz;
    }

    static getBase64Clz(): Wrapper {
        if (!this.Base64_clazz) this.Base64_clazz = Java.use("android.util.Base64");
        return this.Base64_clazz;
    }

    static getByteStringClz(): Wrapper {
        if (!this.ByteString_clazz) this.ByteString_clazz = Java.use("com.android.okhttp.okio.ByteString");
        return this.ByteString_clazz;
    }

    /**
     * 接受java的byte[]，将其转换成string并返回
     * ！！！禁止byte[]之外的类型
     * @param bytes java的byte[]数组
     * @return string 字节数组变为的字符串
     */
    static b2str(bytes: any): string {
        let array;
        try {
            array = Java.array("byte", bytes);
            return this.getStringClz().$new(array)
        } catch (error) {
            Flog.e(this.TAG, `b2str(${bytes}) error: ${error}`)
            return null;
        }
    }

    /**
     * 接受java的byte[]，将其编码成base64字符串并返回
     * ！！！禁止byte[]之外的类型
     * @param bytes java的byte[]数组
     * @return string base64字符串
     */
    static b2b64str(bytes: any): string {
        let array;
        try {
            array = Java.array("byte", bytes)
            return this.getBase64Clz()["encodeToString"](array, 0);
        } catch (error) {
            Flog.e(this.TAG, `b2b64str(${bytes}) error: ${error}`)
            return null;
        }
    }

    /**
     * 接受java的byte[]，将其编码成hex字符串并返回
     * ！！！禁止byte[]之外的类型
     * @param bytes java的byte[]数组
     * @return string hex字符串
     */
    static b2hex(bytes: any): string {
        let array;
        try {
            array = Java.array("byte", bytes)
            return this.getByteStringClz().of(array).hex()
        } catch (error) {
            Flog.e(this.TAG, `b2hex(${bytes}) error: ${error}`)
            return null;
        }
    }
}