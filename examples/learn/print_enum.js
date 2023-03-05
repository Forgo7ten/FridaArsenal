Java.perform(function () {
    Java.choose("com.forgotten.fridatestapp.construct.ConstructoredObject", {
        onMatch: function (instance) {
            // 找到后获取实例field map的值，尝试转为自定义Enum Signal类型
            var venum = Java.cast(instance.color.value, Java.use("com.forgotten.fridatestapp.construct.ConstructoredObject$Signal"));
            console.log("venum:", venum);
            // 调用Enum的方法
            console.log("venum.name():", venum.name());
            console.log("venum.ordinal():", venum.ordinal());
        },
        onComplete: function () {
            console.log("venum: search completed");
        },
    });
});