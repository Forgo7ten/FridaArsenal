function main() {
    Java.perform(function () {
        // 在内存中查找ConstructoredObject类的实例
        Java.choose("com.forgotten.fridatestapp.construct.ConstructoredObject", {
            onMatch: function (instance) {
                // 找到后获取实例field map的值，尝试转为HashMap类型
                var vmap = Java.cast(instance.map.value, Java.use("java.util.HashMap"));
                console.log("vmap:", vmap);
                // 1.
                var key_iterator = vmap.keySet().iterator();
                while (key_iterator.hasNext()) {
                    var key = key_iterator.next().toString();
                    var value = vmap.get(key).toString();
                    console.log(key + ": " + value);
                }
                // 2.
                var entry_iterator = vmap.entrySet().iterator();
                while (entry_iterator.hasNext()) {
                    var entry = Java.cast(entry_iterator.next(),Java.use("java.util.HashMap$Node"));
                    console.log("entry", entry);
                    console.log(entry.getKey(), entry.getValue());
                }
                // 3.
                console.log("vmap.toString():", vmap.toString());
            },
            onComplete: function () {
                console.log("vmap: search completed");
            },
        });
    });
}
