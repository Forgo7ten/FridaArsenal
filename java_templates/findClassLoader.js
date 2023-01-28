/**
 * 通过hook的方式来获取classloader，并设置
 */
function findClassLoaderByHook() {
    let ActivityThread_clazz = Java.use("android.app.ActivityThread");
    ActivityThread_clazz["performLaunchActivity"].implementation = function () {
        let ret = this["performLaunchActivity"].apply(this, arguments);
        Java.classFactory.loader = this.mInitialApplication.value.getClassLoader();
        return ret;
    }
}

/**
 * 同步的方式来寻找classloader
 * @param {String} className 尝试加载的类
 */
function findClassLoaderSync(className) {
    Java.perform(() => {
        let clsLoaders = Java.enumerateClassLoadersSync();
        for (let loader of clsLoaders) {
            try {
                // 如果找到的类加载器 能加载的类有[className]
                if (loader.findClass(className)) {
                    console.log("Successfully found loader");
                    // 设置 java默认的classloader
                    Java.classFactory.loader = loader;
                }
            } catch (error) {
                // console.log("error:" + error);
            }
        }
        func()
    })
}


/**
 * 异步的方式来寻找classloader，之后调用回调函数
 * @param {String} className 尝试加载的类
 * @param {*} callback 回调函数
 */
function findClassLoader(className, callback = () => { }) {
    Java.perform(function () {
        // 枚举内存中的 类加载器
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    // 如果找到的类加载器 能加载的类有[class_name]
                    if (loader.findClass(className)) {
                        console.log("Successfully found loader");
                        console.log(loader);
                        // 设置 java默认的classloader
                        Java.classFactory.loader = loader;
                    }
                } catch (error) {
                    console.log("find error:" + error);
                }
            },
            onComplete: function () {
                console.log("End");
            },
        });
        // 再 使用该类
        callback();
    });
}