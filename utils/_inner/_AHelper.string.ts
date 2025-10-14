import Wrapper = Java.Wrapper;
import {Flog} from "../Flog";
import {_AHelperCore} from "./_AHelper.core";

const {getWrapper} = _AHelperCore
export const _AHelperString = (() => {

    /**
     * 保存Gson对象Wrapper
     * @private
     */
    let _gson_obj: Wrapper | null = null;

    /**
     * 将对象转成json字符串
     * @param {object} obj 要转成json的对象
     * @returns json字符串
     */
    function toGson(obj: Wrapper): string {
        try {
            if (_gson_obj == null) {
                Java.openClassFile("/data/local/tmp/fgson.dex").load();
                _gson_obj = Java.use('com.forgo7ten.gson.Gson');
            }
            return _gson_obj.$new().toJson(obj);
        } catch (error) {
            // md5sum fgson.dex: a7c58b60a7339e6a1207d5207c847bd5  fgson.dex
            Flog.e("toGson", `Please install the jar into the device first.\n  ERROR: ${error}`)
        }
    }


    /**
     * 字节数组转hex字符串 FixMe: writeS8 未测试
     * @param {*} array Wrapper数组
     * @param {*} off 偏移
     * @param {*} len 长度
     */
    function toHexdump(array: Wrapper[], off: number, len: number) {
        off = off || 0;
        len = len || 0;
        len = len == 0 ? array.length : len;
        let ptr = Memory.alloc(len);
        for (let i = 0; i < len; ++i) {
            // @ts-ignore
            Memory.writeS8(ptr.add(i), array[i]);
        }
        return hexdump(ptr, {offset: off, length: len, header: false, ansi: false});
    }

    /**
     * 获得[] Array数组的打印字符串
     * @param array Java任意数组[] 例如byte[]、int[]
     */
    function toStrFromArray(array: any): string {
        // @ts-ignore
        return Java.use("java.util.Arrays").toString(array);
    }

    /**
     * 获得任意列表的打印字符串
     * @param list 任意列表 ArrayList等
     * @param separator 分隔符
     */
    function toStrFromList(list: any, separator: string = "; "): string {
        let len = list.size();
        if (len < 1)
            return "[empty]"
        let logStr = "";
        for (let i = 0; i < len - 1; i++) {
            logStr += `[${i}]${list.get(i)}${separator}`;
        }
        logStr += `[${len - 1}]${list.get(len - 1)}`;
        return logStr;
    }

    /**
     * 获取Java Map转String的字符串
     * @param map Map变量
     * @param separator 分隔符
     */
    function toStrFromMap(map: any, separator: string = "\n"): string {
        map = getWrapper(map);
        let logStr = "";
        let key_iterator = map.keySet().iterator();
        while (key_iterator.hasNext()) {
            let key = key_iterator.next();
            let value = map.get(key);
            logStr += `${key}:${value}${separator}`
        }
        logStr = logStr.slice(0, (0 - separator.length));
        return logStr
    }

    /**
     * 获取Java Set转String的字符串
     * @param set Set变量
     * @param separator 分隔符
     */
    function toStrFromSet(set: any, separator: string = "\n"): string {
        set = getWrapper(set);
        let logStr = "";
        let iterator = set.iterator();
        let i = 0;
        while (iterator.hasNext()) {
            logStr += `[${i}]${iterator.next()}${separator}`;
            i++;
        }
        logStr = logStr.slice(0, (0 - separator.length));
        return logStr;
    }

    /**
     * 获取Java Bundle转String的字符串
     * @param bundle Bundle对象
     * @param separator 分隔符
     */
    function toStrFromBundle(bundle: any, separator: string = ", "): string {
        return toStrFromMap(bundle, separator);
    }

    /**
     * 调用Java实例的toString()方法
     * @param instance Java实例
     */
    function toString(instance: Wrapper) {
        let logStr = `${instance}{  `
        let fields = instance.class.getDeclaredFields();
        fields.forEach(function (field) {
            try {
                field.setAccessible(true);
                var fieldName = field.getName();
                var fieldValue = field.get(instance);
                logStr += `${fieldName}=${fieldValue}, `
            } catch (e) {
                Flog.e("Error accessing field: " + field.getName() + " - " + e);
            }
        });
        logStr = logStr.slice(0, -2) + "  }"
        return logStr
    }

    /**
     * 打印 字节数组转hex字符串
     * @param {*} array Wrapper数组
     * @param {*} off 偏移
     * @param {*} len 长度
     */
    function printHexdump(array: Wrapper[], off: number, len: number) {
        Flog.i(toHexdump(array, off, len))
    }

    /**
     * 打印[] Array数组
     * @param array 任意数组
     */
    function printArray(array: any): void {
        Flog.i("printArray", toStrFromArray(array));
    }

    /**
     * 打印List列表
     * @param list 任意列表
     * @param separator 分隔符
     */
    function printList(list: any, separator: string = "; "): void {
        Flog.i("printList", toStrFromList(list, separator));
    }

    /**
     * 打印JavaMap
     * @param map Map变量
     * @param separator 分隔符
     */
    function printMap(map: any, separator: string = "\n"): void {
        Flog.i("printMap", toStrFromMap(map, separator));
    }

    /**
     * 打印Java Set数据
     * @param set Set变量
     * @param separator 分隔符
     */
    function printSet(set: any, separator: string = "\n"): void {
        Flog.i("printSet", toStrFromSet(set, separator));
    }


    return {
        toGson,
        toHexdump,
        toStrFromArray,
        toStrFromList,
        toStrFromMap,
        toStrFromSet,
        toStrFromBundle,
        toString,
        printHexdump,
        printArray,
        printList,
        printMap,
        printSet,
    };
})()