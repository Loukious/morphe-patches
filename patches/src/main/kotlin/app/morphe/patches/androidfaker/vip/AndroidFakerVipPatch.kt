package app.morphe.patches.androidfaker.vip

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.Compatibility
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.util.returnEarly

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
        method.parameters.size == 1 && method.implementation != null
    }
)

internal object HookStateVipGetterFingerprint : Fingerprint(
    definingClass = "La/qe2;",
    name = "z",
    custom = { method, _ ->
        method.parameters.isEmpty() &&
                (method.returnType == "Z" || method.returnType == "Ljava/lang/Boolean;") &&
                method.implementation != null
    }
)

val androidFakerVipPatch = bytecodePatch(
    name = "Android Faker VIP unlock",
    description = "Bypasses Android Faker native tamper detection and forces VIP state.",
) {
    compatibleWith(COMPATIBILITY_ANDROID_FAKER)

    execute {
        if (NativeDoInitFingerprint.methodOrNull?.implementation != null) {
            NativeDoInitFingerprint.method.returnEarly(true)
        }

        HookStateVipGetterFingerprint.methodOrNull?.let { method ->
            if (method.implementation != null) {
                if (method.returnType == "Z") {
                    method.returnEarly(true)
                } else {
                    method.addInstructions(
                        0,
                        """
                            sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
                            return-object v0
                        """
                    )
                }
            }
        }
    }
}
