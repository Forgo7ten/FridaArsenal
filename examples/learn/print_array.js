function main(){
    Java.perform(function () {
        // Hook Arrays.toString方法 重载char[]
        Java.use("java.util.Arrays").toString.overload("[C").implementation = function () {
            // 打印参数
            console.log("arg = ", arguments[0]);
            // 可正确打印方法1
            // console.log("arg = ", this.toString(arguments[0]));
            console.log("arg = ", Java.use("java.util.Arrays").toString(arguments[0]));
            // 可正确打印方法2
            console.log("arg = ", JSON.stringify(arguments[0]));
            /* 手动构造一个Java array：参数一为类型，参数二为数组 */
            var arg = Java.array("char", ["上", "山", "打", "老", "虎"]);
            var result = this.toString(arg);
            console.log("[NEW]arg,result = ", arg, result);
            return result;
        };
    });
}