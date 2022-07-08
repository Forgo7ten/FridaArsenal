function findClassLoader(className) {
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
        Java.use("[class_name]");
    });
}