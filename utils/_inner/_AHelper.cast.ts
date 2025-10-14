import {Flog} from "../Flog";

export const _AHelperCast = (() => {
    const _CAST_TAG = "Cast"

    /**
     * 接受java的byte[]，将其转换成string并返回
     * ！！！禁止byte[]之外的类型
     * @param bytes java的byte[]数组
     * @return string 字节数组变为的字符串
     */
    function cast_b2str(bytes: any): string {
        let array;
        try {
            array = Java.array("byte", bytes);
            return Java.use("java.lang.String").$new(array)
        } catch (error) {
            Flog.e(_CAST_TAG, `b2str(${bytes}) error: ${error}`)
            return null;
        }
    }

    /**
     * 接受java的byte[]，将其编码成base64字符串并返回
     * ！！！禁止byte[]之外的类型
     * @param bytes java的byte[]数组
     * @return string base64字符串
     */
    function cast_b2b64str(bytes: any): string {
        let array;
        try {
            array = Java.array("byte", bytes)
            return Java.use("android.util.Base64")["encodeToString"](array, 0);
        } catch (error) {
            Flog.e(_CAST_TAG, `b2b64str(${bytes}) error: ${error}`)
            return null;
        }
    }

    /**
     * 接受java的byte[]，将其编码成hex字符串并返回
     * ！！！禁止byte[]之外的类型
     * @param bytes java的byte[]数组
     * @return string hex字符串
     */
    function cast_b2hex(bytes: any): string {
        let array;
        try {
            array = Java.array("byte", bytes)
            return Java.use("com.android.okhttp.okio.ByteString").of(array).hex()
        } catch (error) {
            Flog.e(_CAST_TAG, `b2hex(${bytes}) error: ${error}`)
            return null;
        }
    }

    return {
        cast_b2str,
        cast_b2b64str,
        cast_b2hex,
    }
})()