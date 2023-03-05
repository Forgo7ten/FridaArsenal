// import {android} from "./utils/android";
import {android} from "../../utils/android";
import FindClazz = android.FindClazz;

function main() {
    Java.perform(() => {
        console.log("hihihiiihihihh")
        FindClazz.findAllInterfaces("", "Binding");//
        FindClazz.findAllSuperclasses("",)
        FindClazz.findImpByInterface("android.view.View$OnClickListener", "")
        FindClazz.findChildBySuper("com.forgotten.fridatestapp.construct.Water", "", "")//
    })
}

setImmediate(main)