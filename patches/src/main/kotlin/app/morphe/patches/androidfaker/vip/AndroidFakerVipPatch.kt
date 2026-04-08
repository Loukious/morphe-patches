package app.morphe.patches.androidfaker.vip

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.OpcodesFilter
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.Compatibility
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod.Companion.toMutable
import app.morphe.util.returnEarly
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod

private val COMPATIBILITY_ANDROID_FAKER = Compatibility(
    name = "Android Faker",
    packageName = "com.android1500.androidfaker",
    apkFileType = ApkFileType.APK_REQUIRED,
    appIconColor = 0x14B8A6,
    targets = listOf(
        AppTarget(version = "v2.0.0-beta-9-5", minSdk = 27),
        AppTarget(
            version = null,
            isExperimental = true,
            minSdk = 27,
            description = "Fallback support for unlisted Android Faker versions"
        )
    )
)

internal object NativeDoInitFingerprint : Fingerprint(
    definingClass = "Lcom/androidfaker/core/util/Native;",
    name = "doInit",
    returnType = "Z",
    parameters = listOf("Ljava/lang/String;"),
    custom = { method, _ ->
        method.parameters.size == 1
    }
)

internal object NativeGetDexFingerprint : Fingerprint(
    definingClass = "Lcom/androidfaker/core/util/Native;",
    name = "getDex",
    returnType = "[B",
    parameters = listOf()
)

private fun isHookStateLikeClass(classDef: ClassDef): Boolean {
    return classDef.fields.count { it.type == "Ljava/util/List;" } >= 5 &&
            classDef.fields.count { it.type == "Ljava/lang/String;" } >= 5 &&
            (classDef.fields.any { it.type == "Ljava/lang/Boolean;" } ||
                    classDef.fields.any { it.type == "Z" }) &&
            classDef.fields.any { it.type == "I" } &&
            classDef.methods.any { method ->
                method.returnType == classDef.type && method.parameters.size >= 18
            }
}

internal object HookStateVipGetterFingerprint : Fingerprint(
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "Ljava/lang/Boolean;",
    parameters = listOf(),
    filters = OpcodesFilter.opcodesToFilters(
        Opcode.IGET_OBJECT,
        Opcode.RETURN_OBJECT
    ),
    custom = { method, classDef ->
        method.implementation != null && isHookStateLikeClass(classDef)
    }
)

internal object HookStateVipGetterPrimitiveFingerprint : Fingerprint(
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "Z",
    parameters = listOf(),
    filters = OpcodesFilter.opcodesToFilters(
        Opcode.IGET_BOOLEAN,
        Opcode.RETURN
    ),
    custom = { method, classDef ->
        method.implementation != null && isHookStateLikeClass(classDef)
    }
)

val androidFakerVipPatch = bytecodePatch(
    name = "Android Faker VIP unlock",
    description = "Bypasses Android Faker native tamper detection and forces VIP state.",
) {
    compatibleWith(COMPATIBILITY_ANDROID_FAKER)

    execute {
        fun replaceNativeMethodWithStub(method: com.android.tools.smali.dexlib2.iface.Method, instructions: String) {
            val mutableClass = mutableClassDefBy(method.definingClass)

            val replacementMethod = ImmutableMethod(
                method.definingClass,
                method.name,
                method.parameters,
                method.returnType,
                method.accessFlags and AccessFlags.NATIVE.value.inv() and AccessFlags.ABSTRACT.value.inv(),
                method.annotations,
                method.hiddenApiRestrictions,
                MutableMethodImplementation(1)
            ).toMutable().apply {
                addInstructions(0, instructions)
            }

            mutableClass.methods.removeAll { candidate ->
                candidate.name == method.name &&
                        candidate.returnType == method.returnType &&
                        candidate.parameterTypes == method.parameterTypes
            }
            mutableClass.methods.add(replacementMethod)
        }

        NativeDoInitFingerprint.methodOrNull?.let { method ->
            if (method.implementation != null) {
                method.returnEarly(true)
            } else {
                replaceNativeMethodWithStub(
                    method,
                    """
                        const/4 v0, 0x1
                        return v0
                    """
                )
            }
        }

        NativeGetDexFingerprint.methodOrNull?.let { method ->
            val getDexStub =
                """
                    const/4 v0, 0x0
                    new-array v0, v0, [B
                    return-object v0
                """

            if (method.implementation != null) {
                method.addInstructions(0, getDexStub)
            } else {
                replaceNativeMethodWithStub(method, getDexStub)
            }
        }

        val vipGetterObject = HookStateVipGetterFingerprint.methodOrNull
        if (vipGetterObject?.implementation != null) {
            vipGetterObject.addInstructions(
                0,
                """
                    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
                    return-object v0
                """
            )
        } else if (HookStateVipGetterPrimitiveFingerprint.methodOrNull?.implementation != null) {
            HookStateVipGetterPrimitiveFingerprint.method.returnEarly(true)
        }
    }
}
