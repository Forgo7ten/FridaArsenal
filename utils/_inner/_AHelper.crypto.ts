import {Flog} from "../Flog";
import Wrapper = Java.Wrapper;
import {_AHelperCore} from "./_AHelper.core";
import {_AHelperCast} from "./_AHelper.cast";

const {printStack} = _AHelperCore
const {cast_b2str, cast_b2b64str, cast_b2hex} = _AHelperCast
export const _AHelperCrypto = (() => {
    const _CRYPTO_TAG = "Crypto";

    /**
     * 监控MessageDigest类：md5,sha1,sha256...
     */
    function watch_digest(printStackFlag = true): void {
        const MessageDigest_clazz = Java.use("java.security.MessageDigest");

        function hook_MessageDigest_update(printStackFlag) {
            const MessageDigest_update: Java.MethodDispatcher = MessageDigest_clazz["update"]
            const updateImpl: Java.MethodImplementation = function () {
                let input: Wrapper;
                let ret = this["update"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-MessageDigest", `${this}_${this.hashCode()}.update():${this.algorithm.value}`)
                if (arguments[0].$className != undefined) {
                    input = arguments[0].array();
                } else {
                    input = arguments[0]
                }
                let input_str: string
                if (typeof input === "number") {
                    input_str = `[byte 0x${(<number>input).toString(16)}]`
                } else {
                    input_str = cast_b2str(input)
                }
                if (input) Flog.i(_CRYPTO_TAG + "-MessageDigest", `input=${input}; input_str=${input_str}; input_b64=${cast_b2b64str(input)}`)
                if (printStackFlag) printStack("MessageDigest_update")
                return ret;
            }
            MessageDigest_update.overload('byte').implementation = updateImpl
            MessageDigest_update.overload('java.nio.ByteBuffer').implementation = updateImpl
            MessageDigest_update.overload('[B').implementation = updateImpl
            MessageDigest_update.overload('[B', 'int', 'int').implementation = updateImpl

        }

        function hook_MessageDigest_digest(printStackFlag) {
            const MessageDigest_digest: Java.MethodDispatcher = MessageDigest_clazz["digest"]
            const digestImpl: Java.MethodImplementation = function () {
                let output: Wrapper | null;
                let ret = this["digest"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-MessageDigest", `${this}_${this.hashCode()}.digest():${this.algorithm.value}`)
                switch (arguments.length) {
                    case 0:
                        output = ret;
                        break;
                    case 3:
                        output = arguments[0];
                        break;
                    default:
                        output = null;
                        break;
                }
                if (output) Flog.i(_CRYPTO_TAG + "-MessageDigest", `output=${output}; output_hex=${cast_b2hex(output)}`)
                if (printStackFlag) printStack("MessageDigest_digest")
                return ret;
            }

            MessageDigest_digest.overload().implementation = digestImpl
            // 会调用第一个重载
            // MessageDigest_digest.overload('[B').implementation = digestImpl
            MessageDigest_digest.overload('[B', 'int', 'int').implementation = digestImpl

        }

        Java.perform(() => {
            hook_MessageDigest_update(printStackFlag);
            hook_MessageDigest_digest(printStackFlag);
        })
    }

    /**
     * 监控Cipher类：AES,DES,RSA...
     */
    function watch_cipher(need_printStack = false): void {
        const Cipher_clazz = Java.use("javax.crypto.Cipher");

        function hook_Cipher_init(printStackFlag) {
            const Cipher_chooseProvider: Java.MethodDispatcher = Cipher_clazz["chooseProvider"]
            const IvParameterSpec_clazz = Java.use("javax.crypto.spec.IvParameterSpec")
            /**
             * Cipher.init() 方法的深层次函数，所有的init最终都会执行该方法
             */
            Cipher_chooseProvider.implementation = function (initType: Wrapper, opmode: number, key: Wrapper, paramSpec: Wrapper, params: Wrapper, random: Wrapper) {
                let opmode_str: string = this["getOpmodeString"](opmode);
                Flog.line(_CRYPTO_TAG + "-Cipher", `${this}.init(): ${this.transformation.value} -> ${opmode_str}`)
                if (null != key) {
                    let key_algorithm = key["getAlgorithm"]();
                    let key_format = key["getFormat"]();
                    let key_encoded = key["getEncoded"]();
                    Flog.i(_CRYPTO_TAG + "-Cipher", `Key info: algorithm=${key_algorithm}; format=${key_format}; encoded=${key_encoded}; key_str=${cast_b2str(key_encoded)}; key_b64=${cast_b2b64str(key_encoded)}`)
                }
                if (paramSpec != null) {
                    try {
                        paramSpec = Java.cast(paramSpec, IvParameterSpec_clazz)
                        let iv = paramSpec.getIV()
                        Flog.i(_CRYPTO_TAG + "-Cipher", `IV=${iv}; IV_str=${cast_b2str(iv)}`)
                    } catch (error) {
                        Flog.i(_CRYPTO_TAG + "-Cipher", `paramSpec=${paramSpec.toString()}`)
                    }
                }
                let ret = this["chooseProvider"].apply(this, arguments)
                // console.warn(_WatchCipher.TAG, `${this} -> ${this.spi.value}`)
                if (printStackFlag) printStack("Cipher_init")
                return ret;
            };
        }

        function hook_Cipher_update(printStackFlag) {
            const Cipher_update: Java.MethodDispatcher = Cipher_clazz["update"]
            const updateImpl: Java.MethodImplementation = function () {
                let input: Wrapper | null;
                let output: Wrapper | null;
                let ret = this["update"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-Cipher", `${this}.update():${this.transformation.value}`)
                if (arguments.length == 2) {
                    // .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
                    input = arguments[0].array();
                    output = arguments[1].array();
                } else if (arguments.length <= 3) {
                    // .overload('[B')
                    // .overload('[B', 'int', 'int').
                    input = arguments[0];
                    output = ret;
                } else {
                    // arguments.length > 3
                    // .overload('[B', 'int', 'int', '[B')
                    // .overload('[B', 'int', 'int', '[B', 'int')
                    input = arguments[0];
                    output = arguments[3];
                }
                if (input) Flog.i(_CRYPTO_TAG + "-Cipher", `input=${input}; input_str=${cast_b2str(input)}; input_b64=${cast_b2b64str(input)}`)
                if (output) Flog.i(_CRYPTO_TAG + "-Cipher", `output=${output}; output_hex=${cast_b2hex(output)}; output_b64=${cast_b2b64str(output)}`)
                if (printStackFlag) printStack("Cipher_update")
                return ret;
            }

            Cipher_update.overload('[B').implementation = updateImpl;
            Cipher_update.overload('[B', 'int', 'int').implementation = updateImpl;
            Cipher_update.overload('[B', 'int', 'int', '[B').implementation = updateImpl;
            Cipher_update.overload('[B', 'int', 'int', '[B', 'int').implementation = updateImpl;
            Cipher_update.overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer').implementation = updateImpl;
        }

        function hook_Cipher_doFinal(printStackFlag) {
            const Cipher_doFinal: Java.MethodDispatcher = Cipher_clazz["doFinal"];

            /**
             * FixMe: 没有经过详细的测试
             */
            const doFinalImpl: Java.MethodImplementation = function () {
                let input: Wrapper | null;
                let output: Wrapper | null;
                let ret = this["doFinal"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-Cipher", `${this}.doFinal():${this.transformation.value}`)
                if ([0, 1, 3].includes(arguments.length)) {
                    // .overload()
                    // .overload('[B')
                    // .overload('[B', 'int', 'int').
                    input = arguments[0];
                    output = ret;
                } else if (arguments.length > 3) {
                    // .overload('[B', 'int', 'int', '[B')
                    // .overload('[B', 'int', 'int', '[B', 'int')
                    input = arguments[0];
                    output = arguments[3];
                } else {
                    if (arguments[0].$className === undefined) {
                        // .overload('[B', 'int')
                        input = null;
                        output = arguments[0];
                    } else {
                        // .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
                        input = arguments[0].array();
                        output = arguments[1].array();
                    }
                }
                if (input) Flog.i(_CRYPTO_TAG + "-Cipher", `input=${input}; input_str=${cast_b2str(input)}; input_b64=${cast_b2b64str(input)}`)
                if (output) Flog.i(_CRYPTO_TAG + "-Cipher", `output=${output}; output_hex=${cast_b2hex(output)}; output_b64=${cast_b2b64str(output)}`)
                if (printStackFlag) printStack("Cipher_doFinal")
                return ret;
            }

            Cipher_doFinal.overload().implementation = doFinalImpl
            Cipher_doFinal.overload('[B').implementation = doFinalImpl
            Cipher_doFinal.overload('[B', 'int').implementation = doFinalImpl
            Cipher_doFinal.overload('[B', 'int', 'int').implementation = doFinalImpl
            Cipher_doFinal.overload('[B', 'int', 'int', '[B').implementation = doFinalImpl
            Cipher_doFinal.overload('[B', 'int', 'int', '[B', 'int').implementation = doFinalImpl
            Cipher_doFinal.overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer').implementation = doFinalImpl

        }

        Java.perform(() => {
            hook_Cipher_init(need_printStack);
            hook_Cipher_update(need_printStack);
            hook_Cipher_doFinal(need_printStack);
        })
    }


    /**
     * 监控hmac系列加解密
     */
    function watch_mac(need_printStack = false): void {
        const Mac_clazz = Java.use("javax.crypto.Mac");

        function hook_Mac_init(printStackFlag) {
            const Mac_init: Java.MethodDispatcher = Mac_clazz["init"]
            const IvParameterSpec_clazz = Java.use("javax.crypto.spec.IvParameterSpec")
            const initImpl: Java.MethodImplementation = function () {
                let paramSpec: Wrapper;
                let ret = this["init"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-Hmac", `${this}.init():${this.algorithm.value}`)
                let key: Wrapper = arguments[0];
                let key_algorithm = key["getAlgorithm"]();
                let key_format = key["getFormat"]();
                let key_encoded = key["getEncoded"]();
                if (key) Flog.i(_CRYPTO_TAG + "-Hmac", `Key info: algorithm=${key_algorithm}; format=${key_format}; encoded=${key_encoded}; key_str=${cast_b2str(key_encoded)}; key_b64=${cast_b2b64str(key_encoded)}`)
                if (arguments.length == 2) {
                    // .overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec')
                    paramSpec = arguments[1];
                    try {
                        paramSpec = Java.cast(paramSpec, IvParameterSpec_clazz);
                        let iv = paramSpec.getIV();
                        Flog.i(_CRYPTO_TAG + "-Cipher", `IV=${iv}; IV_str=${cast_b2str(iv)}`);
                    } catch (error) {
                        Flog.i(_CRYPTO_TAG + "-Cipher", `paramSpec=${paramSpec.toString()}`);
                    }
                }
                if (printStackFlag) printStack("Mac_init")
                return ret;
            }
            Mac_init.overload('java.security.Key').implementation = initImpl
            Mac_init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = initImpl

        }

        function hook_Mac_update(printStackFlag) {
            const Mac_update: Java.MethodDispatcher = Mac_clazz["update"];
            const updateImpl: Java.MethodImplementation = function () {
                let input: Wrapper;
                let ret = this["update"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-Hmac", `${this}.update():${this.algorithm.value}`)
                if (arguments[0].$className != undefined) {
                    input = arguments[0].array();
                } else {
                    input = arguments[0];
                }
                let input_str: string
                if (typeof input === "number") {
                    input_str = `[byte 0x${(<number>input).toString(16)}]`
                } else {
                    input_str = cast_b2str(input)
                }
                if (input) Flog.i(_CRYPTO_TAG + "-Hmac", `input=${input}; input_str=${input_str}; input_b64=${cast_b2b64str(input)}`)
                if (printStackFlag) printStack("Mac_update")
                return ret;
            }

            Mac_update.overload('byte').implementation = updateImpl;
            Mac_update.overload('java.nio.ByteBuffer').implementation = updateImpl;
            Mac_update.overload('[B').implementation = updateImpl;
            Mac_update.overload('[B', 'int', 'int').implementation = updateImpl;

        }

        function hook_Mac_doFinal(printStackFlag) {
            const Mac_doFinal: Java.MethodDispatcher = Mac_clazz["doFinal"]
            const doFinalImpl: Java.MethodImplementation = function () {
                let output: Wrapper | null;
                let ret = this["doFinal"].apply(this, arguments)
                Flog.line(_CRYPTO_TAG + "-Hmac", `${this}.doFinal():${this.algorithm.value}`)
                switch (arguments.length) {
                    case 0:
                        output = ret;
                        break;
                    case 2:
                        output = arguments[0];
                        break;
                    default:
                        output = null;
                        break;
                }
                if (output) Flog.i(_CRYPTO_TAG + "-Hmac", `output=${output}; output_hex=${cast_b2hex(output)}`)
                if (printStackFlag) printStack("Mac_doFinal")
                return ret;
            }


            Mac_doFinal.overload().implementation = doFinalImpl
            // Mac_doFinal.overload('[B').implementation = doFinalImpl
            Mac_doFinal.overload('[B', 'int').implementation = doFinalImpl

        }

        Java.perform(() => {
            hook_Mac_init(need_printStack);
            hook_Mac_update(need_printStack);
            hook_Mac_doFinal(need_printStack);
        })
    }

    /**
     * 监控密码加解密相关方法
     * @param stack 控制调用栈的打印，默认为true，打印调用栈
     */
    function watch_crypto(stack: boolean = true): void {
        Java.perform(() => {
            watch_cipher(stack);
            watch_digest(stack);
            watch_mac(stack);
        })
    }

    return {
        watch_digest,
        watch_cipher,
        watch_mac,
        watch_crypto,
    };
})();