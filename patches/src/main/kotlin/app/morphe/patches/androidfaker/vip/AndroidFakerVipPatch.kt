package app.morphe.patches.androidfaker.vip

import app.morphe.patcher.Fingerprint
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

internal object HookStateIsVipUserFingerprint : Fingerprint(
    name = "getIsVipUser",
    returnType = "Ljava/lang/Boolean;",
    parameters = listOf(),
    custom = { _, classDef ->
        classDef.methods.any { method ->
            method.parameters.isEmpty() && method.name in setOf(
                "getSimSlotCount",
                "getSelectedSimCountry",
                "getSelectedSimOperator",
                "getSelectedSimMnc"
            )
        }
    }
)

internal object ProfilesStateIsVipUserFingerprint : Fingerprint(
    name = "getIsVipUser",
    returnType = "Ljava/lang/Boolean;",
    parameters = listOf(),
    custom = { _, classDef ->
        classDef.methods.any { method ->
            method.parameters.isEmpty() && method.name in setOf(
                "getSelectedPackage",
                "getIsLoading"
            )
        } && classDef.methods.none { method ->
            method.name in setOf(
                "getSimSlotCount",
                "getSelectedSimCountry",
                "getSelectedSimOperator",
                "getSelectedSimMnc"
            )
        }
    }
)

internal object GenericIsVipUserFingerprint : Fingerprint(
    name = "getIsVipUser",
    returnType = "Ljava/lang/Boolean;",
    parameters = listOf()
)

internal object NativeDoInitFingerprint : Fingerprint(
    definingClass = "Lcom/androidfaker/core/util/Native;",
    name = "doInit",
    custom = { method, _ ->
        method.parameters.size == 1
    }
)

val androidFakerVipPatch = bytecodePatch(
    name = "Android Faker VIP unlock",
    description = "Forces Android Faker VIP state to be enabled.",
) {
    compatibleWith(COMPATIBILITY_ANDROID_FAKER)

    execute {
        var patchedVipGetter = false

        if (HookStateIsVipUserFingerprint.methodOrNull != null) {
            HookStateIsVipUserFingerprint.method.returnEarly(true)
            patchedVipGetter = true
        }

        if (ProfilesStateIsVipUserFingerprint.methodOrNull != null) {
            ProfilesStateIsVipUserFingerprint.method.returnEarly(true)
            patchedVipGetter = true
        }

        if (!patchedVipGetter && GenericIsVipUserFingerprint.methodOrNull != null) {
            GenericIsVipUserFingerprint.method.returnEarly(true)
        }

        if (NativeDoInitFingerprint.methodOrNull != null) {
            NativeDoInitFingerprint.method.returnEarly(true)
        }
    }
}
