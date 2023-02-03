function filterSystemProperty() {
    Java.perform(function () {
        let System = Java.use("java.lang.System")
        // 过滤代理
        let nullProperties = ["http.proxyHost", "http.proxyPort", "https.proxyHost", "https.proxyPort"]
        function hitRule(propertyStr) {
            for (var i = 0; i < nullProperties.length; i++) {
                if (propertyStr.indexOf(nullProperties[i]) >= 0) {
                    console.log("Hit", propertyStr)
                    return true;
                }
            }
            return false;
        }
        System["getProperty"].overload('java.lang.String').implementation = function (str) {
            if (hitRule(str)) {
                return null
            }
            let ret = this.getProperty(str)
            return ret
        }
        System["getProperty"].overload('java.lang.String', 'java.lang.String').implementation = function (str1, str2) {
            if (hitRule(str1)) {
                return null;
            }
            let ret = this.getProperty(str1, str2)
            // console.log("System.getProperty(" + str1 + "," + str2 + "):", ret)
            return ret
        }
    })
}