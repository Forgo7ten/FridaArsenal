import {_CastHelper} from "./cast_helper";
import {common} from "../common";
import {_Helper} from "./helper";
import Wrapper = Java.Wrapper;
import Flog = common.Flog;
import MethodDispatcher = Java.MethodDispatcher;
import MethodImplementation = Java.MethodImplementation;


export class _WatchCrypto {
    static readonly TAG: string = "WatchCrypto"

    protected static Cipher_clazz: Wrapper;
    protected static MessageDigest_clazz: Wrapper;

    static watch_crypto(): void {
        Java.perform(() => {
            this.watch_cipher();
            this.watch_digest();
        })
    }

    static watch_digest(): void {
        Java.perform(() => {
            this.MessageDigest_clazz = Java.use("java.security.MessageDigest");
            this.hook_MessageDigest_update();
            this.hook_MessageDigest_digest();
        })
    }

    protected static hook_MessageDigest_update() {
        const MessageDigest_update: MethodDispatcher = this.MessageDigest_clazz["update"]
        let updateImpl: MethodImplementation = function () {
            let input: Wrapper;
            let ret = this["update"].apply(this, arguments)
            Flog.line(_WatchCrypto.TAG, `${this}_${this.hashCode()}.update():${this.algorithm.value}`)
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
            if (input) Flog.i(_WatchCrypto.TAG, `input=${input}; input_str=${input_str}`)
            _Helper.printStack("MessageDigest_update")
            return ret;
        }
        MessageDigest_update.overload('byte').implementation = updateImpl
        MessageDigest_update.overload('java.nio.ByteBuffer').implementation = updateImpl
        MessageDigest_update.overload('[B').implementation = updateImpl
        MessageDigest_update.overload('[B', 'int', 'int').implementation = updateImpl

    }

    protected static hook_MessageDigest_digest() {
        const MessageDigest_digest: MethodDispatcher = this.MessageDigest_clazz["digest"]
        let digestImpl: MethodImplementation = function () {
            let output: Wrapper | null;
            let ret = this["digest"].apply(this, arguments)
            Flog.line(_WatchCrypto.TAG, `${this}_${this.hashCode()}.digest():${this.algorithm.value}`)
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
            if (output) Flog.i(_WatchCrypto.TAG, `output=${output}; output_hex=${_CastHelper.b2hex(output)}`)
            _Helper.printStack("MessageDigest_digest")
            return ret;
        }

        MessageDigest_digest.overload().implementation = digestImpl
        // 会调用第一个重载
        // MessageDigest_digest.overload('[B').implementation = digestImpl
        MessageDigest_digest.overload('[B', 'int', 'int').implementation = digestImpl

    }

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
            Flog.line(_WatchCrypto.TAG, `${this}.init(): ${this.transformation.value} -> ${opmode_str}`)
            if (null != key) {
                let key_algorithm = key["getAlgorithm"]();
                let key_format = key["getFormat"]();
                let key_encoded = key["getEncoded"]();
                Flog.i(_WatchCrypto.TAG, `key info: algorithm=${key_algorithm} format=${key_format} encoded=${key_encoded} key_str=${_CastHelper.b2str(key_encoded)}`)
            }
            if (paramSpec != null) {
                paramSpec = Java.cast(paramSpec, IvParameterSpec_clazz)
                let iv = paramSpec.getIV()
                Flog.i(_WatchCrypto.TAG, `IV=${iv} IV_str=${_CastHelper.b2str(iv)}`)
            }
            let ret = this["chooseProvider"].apply(this, arguments)
            // console.warn(_WatchCipher.TAG, `${this} -> ${this.spi.value}`)
            _Helper.printStack("Cipher_init")
            return ret;
        };
    }

    protected static hook_Cipher_update() {
        const Cipher_update: MethodDispatcher = this.Cipher_clazz["update"]
        let updateImpl: MethodImplementation = function () {
            let input: Wrapper | null;
            let output: Wrapper | null;
            let ret = this["update"].apply(this, arguments)
            Flog.line(_WatchCrypto.TAG, `${this}.update():${this.transformation.value}`)
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
            if (input) Flog.i(_WatchCrypto.TAG, `input=${input}; input_str=${_CastHelper.b2str(input)}`)
            if (output) Flog.i(_WatchCrypto.TAG, `output=${output}; output_hex=${_CastHelper.b2hex(output)}; output_b64=${_CastHelper.b2b64str(output)}`)
            _Helper.printStack("Cipher_update")
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

        function print_Cipher_doFinal(cipherObj: Wrapper, input: Wrapper | null, output: Wrapper | null): void {
            Flog.line(_WatchCrypto.TAG, `${cipherObj}.update():${cipherObj.transformation.value}`)
            if (input) Flog.i(_WatchCrypto.TAG, `input=${input}; input_str=${_CastHelper.b2str(input)}`)
            if (output) Flog.i(_WatchCrypto.TAG, `output=${output}; output_hex=${_CastHelper.b2hex(output)}; output_b64=${_CastHelper.b2b64str(output)}`)
            _Helper.printStack("Cipher_update")
        }

        /**
         * FixMe: 没有经过详细的测试
         */
        let doFinalImpl: MethodImplementation = function () {
            let input: Wrapper | null;
            let output: Wrapper | null;
            let ret = this["doFinal"].apply(this, arguments)
            Flog.line(_WatchCrypto.TAG, `${this}.doFinal():${this.transformation.value}`)
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
            if (input) Flog.i(_WatchCrypto.TAG, `input=${input}; input_str=${_CastHelper.b2str(input)}`)
            if (output) Flog.i(_WatchCrypto.TAG, `output=${output}; output_hex=${_CastHelper.b2hex(output)}; output_b64=${_CastHelper.b2b64str(output)}`)
            _Helper.printStack("Cipher_doFinal")
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