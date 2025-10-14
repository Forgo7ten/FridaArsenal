import Wrapper = Java.Wrapper;
import {Flog} from "../Flog";

export const _AHelperCore = (() => {
    const _HELPER_TAG = "Helper"

    /**
     * 检查类名，过滤系统类和基本类型。返回false表示命中，需要过滤掉
     * @param name 类名
     * @returns boolean
     */
    function filterSysClass(name: string): boolean {
        return !(name.indexOf(".") < 0
            || name.startsWith("[")
            || name.startsWith("android")
            || name.startsWith("dalvik")
            || name.startsWith("kotlin")
            || name.startsWith("java")
            || name.startsWith("sun.")
            || name.startsWith("org.")
            || name.startsWith("com.android")
            || name.startsWith("com.google")
            || name.startsWith("libcore.")
            || name.startsWith("de.robv.android.xposed.")
        );
    }

    /**
     * Java.cast java对象
     * @param jobj java对象
     * @param cls 认为的该对象可能的类名或类，可省略
     * @returns 强转之后的Java Wrapper
     */
    function getWrapper(jobj: Wrapper, cls: Wrapper | string = null): Wrapper {
        if (jobj == null) {
            Flog.e(_HELPER_TAG, `getWrapper() jobj == null`);
            return null;
        }
        try {
            cls = cls || jobj.$className;
            if (typeof cls === "string") {
                return Java.cast(jobj, Java.use(cls));
            } else {
                return Java.cast(jobj, cls);
            }
        } catch (error) {
            Flog.e(_HELPER_TAG, `getWrapper(${jobj}) ERROR:${error}`)
        }
        return null;
    }


    /**
     * 获得Java调用栈字符串
     */
    function getStack(): string {
        let throwable = "";
        Java.perform(function () {
            throwable = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        });
        return throwable;
    }

    /**
     * 打印Java调用栈
     * @param TAG TAG，可选
     */
    function printStack(TAG: string = ""): void {
        console.log("========================================  " + TAG + " Stack strat  ========================================");
        console.log(getStack());
        console.log("=========================================  " + TAG + " Stack end  =========================================\r\n");
    }

    let _ClassClz: Wrapper;
    let _ObjectClz: Wrapper;

    /**
     * 通过Java对象Wrapper，拿到对象的全类名
     * @param {Wrapper} obj 未知对象
     * @returns 对象的全类名
     */
    function getClsNameFromObj(obj: Wrapper): string {
        _ClassClz = _ClassClz || Java.use("java.lang.Class");
        _ObjectClz = _ObjectClz || Java.use("java.lang.Object");
        return _ClassClz.getName.call(_ObjectClz.getClass.call(obj));
    }


    /**
     * 获得App Context
     */
    function getAppCtx() {
        let context = null;
        Java.perform(function () {
            let currentApplication = Java.use("android.app.ActivityThread").currentApplication();
            context = Java.retain(currentApplication.getApplicationContext());
        })
        return context;
    }

    /**
     * 通过反射来获取java对象 成员的值
     * @param {Wrapper} object java对象
     * @param {string} fieldName 字段名
     * @returns 对象成员的值或null
     */
    function getFieldValue(object: Wrapper, fieldName: string): Wrapper {
        let field = object.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        let fieldValue = field.get(object);
        if (null === fieldValue) {
            Flog.w(_HELPER_TAG, `getFieldValue(${object.$className}, ${fieldName}) = NULL`);
            return null;
        }
        return getWrapper(fieldValue);
    }

    return {
        filterSysClass,
        getWrapper,
        getStack,
        printStack,
        getClsNameFromObj,
        getAppCtx,
        getFieldValue,
    };
})()