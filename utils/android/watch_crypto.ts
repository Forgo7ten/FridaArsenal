import {_CastHelper} from "./cast_helper";
import {common} from "../common";
import {_Helper} from "./helper";
import Wrapper = Java.Wrapper;
import Flog = common.Flog;
import MethodDispatcher = Java.MethodDispatcher;
import MethodImplementation = Java.MethodImplementation;


export class _WatchCrypto {
    static readonly TAG: string = "WatchCrypto"
    static readonly Cipher_TAG: string = "Cipher"
    static readonly MessageDigest_TAG: string = "MessageDigest"
    static readonly HMac_TAG: string = "Hmac"

    protected static Cipher_clazz: Wrapper;
    protected static MessageDigest_clazz: Wrapper;
    protected static Mac_clazz: Wrapper;

    /**
     * 控制调用栈的打印
     * @private
     */
    protected static _stack_controller: boolean;

    /**
     * 监控密码加解密相关方法
     * @param stack 控制调用栈的打印，默认为true，打印调用栈
     */
    static watch_crypto(stack: boolean = true): void {
        _WatchCrypto._stack_controller = stack

        Java.perform(() => {
            this.watch_cipher();
            this.watch_digest();
            this.watch_mac();
        })
    }

    /**
     * 监控hmac系列加解密
     */
    static watch_mac(): void {
        Java.perform(() => {
            this.Mac_clazz = Java.use("javax.crypto.Mac");
            this.hook_Mac_init();
            this.hook_Mac_update();
            this.hook_Mac_doFinal();
        })
    }

    protected static hook_Mac_init() {
        const Mac_init: MethodDispatcher = this.Mac_clazz["init"]
        const IvParameterSpec_clazz = Java.use("javax.crypto.spec.IvParameterSpec")
        const initImpl: MethodImplementation = function () {
            let paramSpec: Wrapper;
            let ret = this["init"].apply(this, arguments)
            Flog.line(_WatchCrypto.HMac_TAG, `${this}.init():${this.algorithm.value}`)
            let key: Wrapper = arguments[0];
            let key_algorithm = key["getAlgorithm"]();
            let key_format = key["getFormat"]();
            let key_encoded = key["getEncoded"]();
            if (key) Flog.i(_WatchCrypto.HMac_TAG, `Key info: algorithm=${key_algorithm}; format=${key_format}; encoded=${key_encoded}; key_str=${_CastHelper.b2str(key_encoded)}; key_b64=${_CastHelper.b2b64str(key_encoded)}`)
            if (arguments.length == 2) {
                // .overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec')
                paramSpec = arguments[1];
                try {
                    paramSpec = Java.cast(paramSpec, IvParameterSpec_clazz);
                    let iv = paramSpec.getIV();
                    Flog.i(_WatchCrypto.Cipher_TAG, `IV=${iv}; IV_str=${_CastHelper.b2str(iv)}`);
                } catch (error) {
                    Flog.i(_WatchCrypto.Cipher_TAG, `paramSpec=${paramSpec.toString()}`);
                }
            }
            if (_WatchCrypto._stack_controller) _Helper.printStack("Mac_init")
            return ret;
        }
        Mac_init.overload('java.security.Key').implementation = initImpl
        Mac_init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = initImpl

    }

    protected static hook_Mac_update() {
        const Mac_update: MethodDispatcher = this.Mac_clazz["update"];
        const updateImpl: MethodImplementation = function () {
            let input: Wrapper;
            let ret = this["update"].apply(this, arguments)
            Flog.line(_WatchCrypto.HMac_TAG, `${this}.update():${this.algorithm.value}`)
            if (arguments[0].$className != undefined) {
                input = arguments[0].array();
            } else {
                input = arguments[0];
            }
            let input_str: string
            if (typeof input === "number") {
                input_str = `[byte 0x${(<number>input).toString(16)}]`
            } else {
                input_str = _CastHelper.b2str(input)
            }
            if (input) Flog.i(_WatchCrypto.HMac_TAG, `input=${input}; input_str=${input_str}; input_b64=${_CastHelper.b2b64str(input)}`)
            if (_WatchCrypto._stack_controller) _Helper.printStack("Mac_update")
            return ret;
        }

        Mac_update.overload('byte').implementation = updateImpl;
        Mac_update.overload('java.nio.ByteBuffer').implementation = updateImpl;
        Mac_update.overload('[B').implementation = updateImpl;
        Mac_update.overload('[B', 'int', 'int').implementation = updateImpl;

    }

    protected static hook_Mac_doFinal() {
        const Mac_doFinal: MethodDispatcher = this.Mac_clazz["doFinal"]
        const doFinalImpl: MethodImplementation = function () {
            let output: Wrapper | null;
            let ret = this["doFinal"].apply(this, arguments)
            Flog.line(_WatchCrypto.HMac_TAG, `${this}.doFinal():${this.algorithm.value}`)
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
            if (output) Flog.i(_WatchCrypto.HMac_TAG, `output=${output}; output_hex=${_CastHelper.b2hex(output)}`)
            if (_WatchCrypto._stack_controller) _Helper.printStack("Mac_doFinal")
            return ret;
        }


        Mac_doFinal.overload().implementation = doFinalImpl
        // Mac_doFinal.overload('[B').implementation = doFinalImpl
        Mac_doFinal.overload('[B', 'int').implementation = doFinalImpl

    }

    /**
     * 监控MessageDigest类：md5,sha1,sha256...
     */
    static watch_digest(): void {
        Java.perform(() => {
            this.MessageDigest_clazz = Java.use("java.security.MessageDigest");
            this.hook_MessageDigest_update();
            this.hook_MessageDigest_digest();
        })
    }

    protected static hook_MessageDigest_update() {
        const MessageDigest_update: MethodDispatcher = this.MessageDigest_clazz["update"]
        const updateImpl: MethodImplementation = function () {
            let input: Wrapper;
            let ret = this["update"].apply(this, arguments)
            Flog.line(_WatchCrypto.MessageDigest_TAG, `${this}_${this.hashCode()}.update():${this.algorithm.value}`)
            if (arguments[0].$className != undefined) {
                input = arguments[0].array();
            } else {
                input = arguments[0]
            }
            let input_str: string
            if (typeof input === "number") {
                input_str = `[byte 0x${(<number>input).toString(16)}]`
            } else {
                input_str = _CastHelper.b2str(input)
            }
            if (input) Flog.i(_WatchCrypto.MessageDigest_TAG, `input=${input}; input_str=${input_str}; input_b64=${_CastHelper.b2b64str(input)}`)
            if (_WatchCrypto._stack_controller) _Helper.printStack("MessageDigest_update")
            return ret;
        }
        MessageDigest_update.overload('byte').implementation = updateImpl
        MessageDigest_update.overload('java.nio.ByteBuffer').implementation = updateImpl
        MessageDigest_update.overload('[B').implementation = updateImpl
        MessageDigest_update.overload('[B', 'int', 'int').implementation = updateImpl

    }

    protected static hook_MessageDigest_digest() {
        const MessageDigest_digest: MethodDispatcher = this.MessageDigest_clazz["digest"]
        const digestImpl: MethodImplementation = function () {
            let output: Wrapper | null;
            let ret = this["digest"].apply(this, arguments)
            Flog.line(_WatchCrypto.MessageDigest_TAG, `${this}_${this.hashCode()}.digest():${this.algorithm.value}`)
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
            if (output) Flog.i(_WatchCrypto.MessageDigest_TAG, `output=${output}; output_hex=${_CastHelper.b2hex(output)}`)
            if (_WatchCrypto._stack_controller) _Helper.printStack("MessageDigest_digest")
            return ret;
        }

        MessageDigest_digest.overload().implementation = digestImpl
        // 会调用第一个重载
        // MessageDigest_digest.overload('[B').implementation = digestImpl
        MessageDigest_digest.overload('[B', 'int', 'int').implementation = digestImpl

    }

    /**
     * 监控Cipher类：AES,DES,RSA...
     */
    static watch_cipher(): void {
        Java.perform(() => {
            this.Cipher_clazz = Java.use("javax.crypto.Cipher");

            this.hook_Cipher_init();
            this.hook_Cipher_update();
            this.hook_Cipher_doFinal();
        })
    }

    protected static hook_Cipher_init() {
        const Cipher_chooseProvider: MethodDispatcher = this.Cipher_clazz["chooseProvider"]
        const IvParameterSpec_clazz = Java.use("javax.crypto.spec.IvParameterSpec")
        /**
         * Cipher.init() 方法的深层次函数，所有的init最终都会执行该方法
         */
        Cipher_chooseProvider.implementation = function (initType: Wrapper, opmode: number, key: Wrapper, paramSpec: Wrapper, params: Wrapper, random: Wrapper) {
            let opmode_str: string = this["getOpmodeString"](opmode);
            Flog.line(_WatchCrypto.Cipher_TAG, `${this}.init(): ${this.transformation.value} -> ${opmode_str}`)
            if (null != key) {
                let key_algorithm = key["getAlgorithm"]();
                let key_format = key["getFormat"]();
                let key_encoded = key["getEncoded"]();
                Flog.i(_WatchCrypto.Cipher_TAG, `Key info: algorithm=${key_algorithm}; format=${key_format}; encoded=${key_encoded}; key_str=${_CastHelper.b2str(key_encoded)}; key_b64=${_CastHelper.b2b64str(key_encoded)}`)
            }
            if (paramSpec != null) {
                try {
                    paramSpec = Java.cast(paramSpec, IvParameterSpec_clazz)
                    let iv = paramSpec.getIV()
                    Flog.i(_WatchCrypto.Cipher_TAG, `IV=${iv}; IV_str=${_CastHelper.b2str(iv)}`)
                } catch (error) {
                    Flog.i(_WatchCrypto.Cipher_TAG, `paramSpec=${paramSpec.toString()}`)
                }
            }
            let ret = this["chooseProvider"].apply(this, arguments)
            // console.warn(_WatchCipher.TAG, `${this} -> ${this.spi.value}`)
            if (_WatchCrypto._stack_controller) _Helper.printStack("Cipher_init")
            return ret;
        };
    }

    protected static hook_Cipher_update() {
        const Cipher_update: MethodDispatcher = this.Cipher_clazz["update"]
        const updateImpl: MethodImplementation = function () {
            let input: Wrapper | null;
            let output: Wrapper | null;
            let ret = this["update"].apply(this, arguments)
            Flog.line(_WatchCrypto.Cipher_TAG, `${this}.update():${this.transformation.value}`)
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
            if (input) Flog.i(_WatchCrypto.Cipher_TAG, `input=${input}; input_str=${_CastHelper.b2str(input)}; input_b64=${_CastHelper.b2b64str(input)}`)
            if (output) Flog.i(_WatchCrypto.Cipher_TAG, `output=${output}; output_hex=${_CastHelper.b2hex(output)}; output_b64=${_CastHelper.b2b64str(output)}`)
            if (_WatchCrypto._stack_controller) _Helper.printStack("Cipher_update")
            return ret;
        }

        Cipher_update.overload('[B').implementation = updateImpl;
        Cipher_update.overload('[B', 'int', 'int').implementation = updateImpl;
        Cipher_update.overload('[B', 'int', 'int', '[B').implementation = updateImpl;
        Cipher_update.overload('[B', 'int', 'int', '[B', 'int').implementation = updateImpl;
        Cipher_update.overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer').implementation = updateImpl;
    }

    protected static hook_Cipher_doFinal() {
        const Cipher_doFinal: MethodDispatcher = this.Cipher_clazz["doFinal"];

        /**
         * FixMe: 没有经过详细的测试
         */
        const doFinalImpl: MethodImplementation = function () {
            let input: Wrapper | null;
            let output: Wrapper | null;
            let ret = this["doFinal"].apply(this, arguments)
            Flog.line(_WatchCrypto.Cipher_TAG, `${this}.doFinal():${this.transformation.value}`)
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
            if (input) Flog.i(_WatchCrypto.Cipher_TAG, `input=${input}; input_str=${_CastHelper.b2str(input)}; input_b64=${_CastHelper.b2b64str(input)}`)
            if (output) Flog.i(_WatchCrypto.Cipher_TAG, `output=${output}; output_hex=${_CastHelper.b2hex(output)}; output_b64=${_CastHelper.b2b64str(output)}`)
            if (_WatchCrypto._stack_controller) _Helper.printStack("Cipher_doFinal")
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


}