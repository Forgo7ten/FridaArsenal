/**
 * 十六进制打印数组
 * @param {*} array 数组
 * @param {*} off 偏移
 * @param {*} len 长度
 */
function jhexdump(array, off, len) {
    off = off || 0;
    len = len || 0;
    var llen = len == 0 ? array.length : len;
    var ptr = Memory.alloc(llen);
    for (var i = 0; i < llen; ++i) Memory.writeS8(ptr.add(i), array[i]);
    //console.log(hexdump(ptr, { offset: off, length: len, header: false, ansi: false }));
    console.log(hexdump(ptr, { offset: off == 0 ? 0 : off, length: llen, header: false, ansi: false }));
}
