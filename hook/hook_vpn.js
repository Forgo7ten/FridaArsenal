function hook_vpn(){
    Java.perform(function(){
        var NetworkInterface  = Java.use("java.net.NetworkInterface")
        var NetworkInfo = Java.use("android.net.NetworkInfo")
        var NetworkCapabilities = Java.use("android.net.NetworkCapabilities")
        NetworkInterface.getNetworkInterfaces.implementation = function(){
            console.log("hook_vpn NetworkInterface.getNetworkInterfaces()")
            let ret = this.getNetworkInterfaces()
            return null;
        }
        NetworkCapabilities.isConnected.implementation = function(){
            console.log("hook_vpn NetworkCapabilities.isConnected()")
            return false
        }

        NetworkInterface.getName.implementation = function(){
            console.log("hook_vpn NetworkInterface.getName()")
            return ""
        }
        
        NetworkInfo.hasTransport.implementation=function(){
            console.log("hook_vpn NetworkInfo.hasTransport()")
            return false
        }
    })
}