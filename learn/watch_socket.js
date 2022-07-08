/**
 * HOOK socket;打印socket收发包
 */

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

/*
HTTP
java.net.InetSocketAddress.InetSocketAddress(www.baidu.com/180.101.49.12, 80)
java.net.InetSocketAddress$InetSocketAddressHolder.InetSocketAddress$InetSocketAddressHolder((none), www.baidu.com/180.101.49.12, 80, (none))
java.net.InetSocketAddress.InetSocketAddress(/192.168.0.2, 43066)
java.net.InetSocketAddress$InetSocketAddressHolder.InetSocketAddress$InetSocketAddressHolder((none), /192.168.0.2, 43066, (none))
java.net.SocketInputStream.SocketInputStream(Socket[addr=www.baidu.com/180.101.49.12,port=80,localport=43066])
java.net.SocketOutputStream.SocketOutputStream(Socket[addr=www.baidu.com/180.101.49.12,port=80,localport=43066])
HTTPS
java.net.InetSocketAddress.InetSocketAddress(www.baidu.com/180.101.49.12, 443)
java.net.Socket$2.Socket$2(Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405]) 
java.net.SocketInputStream.SocketInputStream(Socket[addr=www.baidu.com/180.101.49.12,port=443,localport=44405])
java.net.SocketOutputStream.SocketOutputStream(Socket[addr=www.baidu.com/180.101.49.12,port=443,localport=44405])
com.android.org.conscrypt.ConscryptFileDescriptorSocket.ConscryptFileDescriptorSocket(Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405], www.baidu.com, 443, true, com.android.org.conscrypt.SSLParametersImpl@2ccad02)
com.android.org.conscrypt.OpenSSLSocketImpl.OpenSSLSocketImpl(Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405], www.baidu.com, 443, true)
com.android.org.conscrypt.AbstractConscryptSocket.AbstractConscryptSocket(Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405], www.baidu.com, 443, true)   
com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream.ConscryptFileDescriptorSocket$SSLOutputStream(SSL socket over Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405])
com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream.ConscryptFileDescriptorSocket$SSLInputStream(SSL socket over Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405])
*/

/* HOOK所有带"socket"类的$init方法来获取 */
function hook_Address() {
    Java.perform(function () {
        Java.use("java.net.InetSocketAddress").$init.overload("java.net.InetAddress", "int").implementation = function (addr, int) {
            var result = this.$init(addr, int);
            if (addr.isSiteLocalAddress()) {
                console.log("Local address => ", addr.toString(), " port is => ", int);
            } else {
                console.log("Server address => ", addr.toString(), " port is => ", int);
            }

            return result;
        };
    });
}

/* Android8.1 http socket包截获 | HOOK所有带"socket"的类的所有方法获取 */
function hook_socket() {
    Java.perform(function () {
        console.log("Android8.1 hook_socket");

        Java.use("java.net.SocketOutputStream").write.overload("[B", "int", "int").implementation = function (bytearry, offest, len) {
            var result = this.write(bytearry, offest, len);
            console.log("HTTP write result,bytearry,int1,int2=>", result, bytearry, offest, len);

            // var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())

            jhexdump(bytearry, offest, len);
            return result;
        };

        Java.use("java.net.SocketInputStream").read.overload("[B", "int", "int").implementation = function (bytearry, offest, len) {
            var result = this.read(bytearry, offest, len);
            console.log("HTTP read result,bytearry,int1,int2=>", result, bytearry, offest, len);
            // var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            jhexdump(bytearry, offest, len);
            return result;
        };
    });
}

/* Android8.1 https socket包截获 | HOOK所有带"socket"的类的所有方法获取 */
function hook_SSLsocketandroid8() {
    Java.perform(function () {
        console.log("Android8.1 hook_SSLsocket");

        Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream").write.overload("[B", "int", "int").implementation = function (bytearry, offest, len) {
            var result = this.write(bytearry, offest, len);
            console.log("HTTPS write result,bytearry,int1,int2=>", result, bytearry, offest, len);
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            jhexdump(bytearry, offest, len);

            return result;
        };

        Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream").read.overload("[B", "int", "int").implementation = function (bytearry, offest, len) {
            var result = this.read(bytearry, offest, len);
            console.log("HTTPS read result,bytearry,int1,int2=>", result, bytearry, offest, len);
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            jhexdump(bytearry, offest, len);

            return result;
        };
    });
}

/* Android10 https socket包截获 | HOOK所有带"socket"的类的所有方法获取 */
function hook_SSLsocket2android10() {
    Java.perform(function () {
        console.log(" hook_SSLsocket2");
        var ByteString = Java.use("com.android.okhttp.okio.ByteString");
        Java.use("com.android.org.conscrypt.NativeCrypto").SSL_write.implementation = function (long, NS, fd, NC, bytearray, int1, int2, int3) {
            var result = this.SSL_write(long, NS, fd, NC, bytearray, int1, int2, int3);
            console.log("SSL_write(long,NS,fd,NC,bytearray,int1,int2,int3),result=>", long, NS, fd, NC, bytearray, int1, int2, int3, result);
            console.log(ByteString.of(bytearray).hex());
            return result;
        };
        Java.use("com.android.org.conscrypt.NativeCrypto").SSL_read.implementation = function (long, NS, fd, NC, bytearray, int1, int2, int3) {
            var result = this.SSL_read(long, NS, fd, NC, bytearray, int1, int2, int3);
            console.log("SSL_read(long,NS,fd,NC,bytearray,int1,int2,int3),result=>", long, NS, fd, NC, bytearray, int1, int2, int3, result);
            console.log(ByteString.of(bytearray).hex());
            return result;
        };
    });
}

function main() {
    hook_Address();
    hook_socket();
    hook_SSLsocketandroid8();
}
setImmediate(main);
