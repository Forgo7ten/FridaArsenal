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
     * @param bytes java的byte[]数组
     * @return string 字节数组变为的字符串
     */
    static b2str(bytes: Wrapper): string {
        try {
            if (bytes.$className == '[B') {
                // @ts-ignore
                bytes = Java.array("byte", bytes)
            }
            return this.String_clazz.$new(bytes)
        } catch (error) {
            Flog.d(this.TAG, `b2str argument type error.`)
            // @ts-ignore
            return bytes;
        }
    }

    /**
     * 接受java的byte[]，将其编码成base64字符串并返回
     * @param bytes java的byte[]数组
     * @return string base64字符串
     */
    static b2b64str(bytes: Wrapper): string {
        try {
            if (bytes.$className == '[B') {
                // @ts-ignore
                bytes = Java.array("byte", bytes)
            }
            return this.Base64_clazz["encodeToString"](bytes, 0);
        } catch (error) {
            Flog.d(this.TAG, `b2b64str argument type error.`)
            // @ts-ignore
            return bytes;
        }
    }

    /**
     * 接受java的byte[]，将其编码成hex字符串并返回
     * @param bytes java的byte[]数组
     * @return string hex字符串
     */
    static b2hex(bytes: Wrapper): string {
        try {
            if (bytes.$className == '[B') {
                // @ts-ignore
                bytes = Java.array("byte", bytes)
            }
            return this.ByteString_clazz.of(bytes).hex()
        } catch (error) {
            Flog.d(this.TAG, `b2hex argument type error.`)
            // @ts-ignore
            return bytes;
        }
    }
}