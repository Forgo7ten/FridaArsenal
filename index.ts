
function main() {
    Java.perform(() => {
        console.log("hello Frida.")
    })
}

setImmediate(main)
