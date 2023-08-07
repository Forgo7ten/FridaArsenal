import {common} from "../common";
import Wrapper = Java.Wrapper;
import Flog = common.Flog;

export class _CastHelper {
    static readonly TAG = "CastHelper"
    static String_clazz: Wrapper = Java.use("java.lang.String")
    static Base64_clazz: Wrapper = Java.use("android.util.Base64");
    static ByteString_clazz: Wrapper = Java.use("com.android.okhttp.okio.ByteString");

    /**
     * 接受java的byte[]，将其转换成string并返回
     * ！！！禁止byte[]之外的类型
     * @param bytes java的byte[]数组
     * @return string 字节数组变为的字符串
     */
    static b2str(bytes: any[]): string {
        let array;
        try {
            array = Java.array("byte", bytes);
            return this.String_clazz.$new(array)
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
    static b2b64str(bytes: any[]): string {
        let array;
        try {
            array = Java.array("byte", bytes)
            return this.Base64_clazz["encodeToString"](array, 0);
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
    static b2hex(bytes: any[]): string {
        let array;
        try {
            array = Java.array("byte", bytes)
            return this.ByteString_clazz.of(array).hex()
        } catch (error) {
            Flog.e(this.TAG, `b2hex(${bytes}) error: ${error}`)
            return null;
        }
    }
}