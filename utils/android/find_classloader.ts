import {common} from "../common";
import Flog = common.Flog;
import Wrapper = Java.Wrapper;

/**
 * FindClassLoader:寻找可能的ClassLoader并设置
 */
export class _FindClassloader {
    // FixMe: 没有合适案例来详细的测试
    static readonly TAG: string = "FindClassLoader"


    /**
     * 通过hook的方式来获取classloader，并设置
     */
    static findClassLoaderByHook(): void {
        let ActivityThread_clazz = Java.use("android.app.ActivityThread");
        ActivityThread_clazz["performLaunchActivity"].implementation = function () {
            let ret: Wrapper = this["performLaunchActivity"].apply(this, arguments);
            // @ts-ignore
            Java.classFactory.loader = this.mInitialApplication.value.getClassLoader();
            return ret;
        }
    }

    /**
     * 同步的方式来寻找classloader
     * @param {String} className 尝试加载的类
     */
    static findClassLoaderSync(className: string): Wrapper | void {
        if (className == undefined) {
            Flog.e(_FindClassloader.TAG, "className == undefined, return");
            return;
        }
        let clsLoaders: Wrapper[] = Java.enumerateClassLoadersSync();
        for (let loader of clsLoaders) {
            try {
                // 如果找到的类加载器 能加载的类有[className]
                if (loader.findClass(className)) {
                    Flog.i(_FindClassloader.TAG, "Successfully found loader");
                    // @ts-ignore
                    Java.classFactory.loader = loader;
                    return loader;
                }
            } catch (error) {
            }
        }
    }


    /**
     * 异步的方式来寻找classloader，之后调用回调函数
     * @param className 尝试加载的类
     * @param onCallback 寻找到ClassLoader之后要回调的函数，默认为空
     */
    static findClassLoader(className: string, onCallback: () => void = () => {
    }): void {
        let found: boolean = false;
        if (className == undefined) {
            Flog.w(_FindClassloader.TAG, "className == undefined, return");
            return;
        }
        // 枚举内存中的 类加载器
        Java.enumerateClassLoaders({
            onMatch: function (loader: Wrapper) {
                try {
                    if (found) return;
                    // Flog.d(_FindClassloader.TAG, `Found loader: ${loader}`)
                    // 如果找到的类加载器 能加载的类有[class_name]//
                    if (loader.findClass(className)) {
                        // @ts-ignore
                        Java.classFactory.loader = loader;
                        onCallback();
                        Flog.i(_FindClassloader.TAG, "Successfully found loader");
                        found = true;
                    }
                } catch (error) {
                }
            },
            onComplete: function () {
                Flog.d(_FindClassloader.TAG, "findClassLoader End");
            },
        });

    }
}

