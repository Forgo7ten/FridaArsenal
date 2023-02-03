function hook_vpn(){
    Java.perform(function(){
        var NetworkInterface  = Java.use("java.net.NetworkInterface")
        NetworkInterface.getNetworkInterfaces.implementation = function(){
            console.log("hook_vpn NetworkInterface.getNetworkInterfaces()")
            let ret = this.getNetworkInterfaces()
            return null;
        }
    })
}