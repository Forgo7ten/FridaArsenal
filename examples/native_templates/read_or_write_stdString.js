function readStdString(str) {
    var isTiny = (str.readU8 & 1) === 0;
    if (isTiny) {
        return str.add(1).readUtf8String();
    }
    return str
        .add(2 * Process.pointerSize)
        .readPointer()
        .readUtf8String();
}

function writeStdString(str, content) {
    var isTiny = (str.readU8() & 1) === 0;
    if (isTiny) {
        str.add(1).writeUtf8String(content);
    } else {
        str.add(2 * Process.pointerSize)
            .readPointer()
            .writeUtf8String(content);
    }
}