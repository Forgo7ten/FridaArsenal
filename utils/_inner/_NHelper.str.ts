export const _NHelperStr = (() => {

    /**
     * 从std::string对象中取到str
     * @param strPtr 地址指针
     */
    function getStdStringStr(strPtr: NativePointer): string {
        let isTiny = (strPtr.readU8() & 1) === 0;
        if (isTiny) {
            return strPtr.add(1).readUtf8String();
        }
        return strPtr
            .add(2 * Process.pointerSize)
            .readPointer()
            .readUtf8String();
    }

    /**
     * 从jstring对象中取到str
     * @param strPtr 地址指针
     */
    function getJstringStr(strPtr: NativePointer): string {
        return Java.vm.getEnv().getStringUtfChars(strPtr, null).readCString();
    }

    /**
     * 新建一个jstring对象
     * @param str 字符串值
     */
    function newJstring(str: string): NativePointer {
        return Java.vm.getEnv().newStringUtf(str);
    }

    return {
        getStdStringStr,
        getJstringStr,
        newJstring,
    };
})()