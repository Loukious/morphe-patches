package app.morphe.patches.androidfaker.vip

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.OpcodesFilter
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.Compatibility
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod.Companion.toMutable
import app.morphe.util.findMutableMethodOf
import app.morphe.util.returnEarly
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21c
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction35c
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
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

// ─── Native Anti-Tamper ─────────────────────────────────────────────────────
// Native.doInit(String) → true  (bypasses anti-tamper init)
internal object NativeDoInitFingerprint : Fingerprint(
    definingClass = "Lcom/androidfaker/core/util/Native;",
    name = "doInit",
    returnType = "Z",
    parameters = listOf("Ljava/lang/String;"),
    custom = { method, _ -> method.parameters.size == 1 }
)

// Native.getDex() → byte[]  (serves the spoofing DEX payload)
internal object NativeGetDexFingerprint : Fingerprint(
    definingClass = "Lcom/androidfaker/core/util/Native;",
    name = "getDex",
    returnType = "[B",
    parameters = listOf()
)

// ─── Core VIP Check ─────────────────────────────────────────────────────────
// ms6 class: has exactly 2 fields (String + List), and a no-arg boolean method.
// ms6.b() compares vipDueDate > currentTime → this IS the VIP gate.
private fun isVipGateClass(classDef: ClassDef): Boolean {
    val fields = classDef.fields.toList()
    return fields.size == 2 &&
            fields.count { it.type == "Ljava/lang/String;" } == 1 &&
            fields.count { it.type == "Ljava/util/List;" } == 1
}

internal object CoreIsVipFingerprint : Fingerprint(
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "Z",
    parameters = listOf(),
    custom = { method, classDef ->
        method.implementation != null && isVipGateClass(classDef)
    }
)

// ─── Account Data (ms6$a) ───────────────────────────────────────────────────
// Inner class with exactly 5 fields: String, String, boolean, int, long
private fun isAccountDataClass(classDef: ClassDef): Boolean {
    val fields = classDef.fields.toList()
    return fields.size == 5 &&
            fields.count { it.type == "Ljava/lang/String;" } == 2 &&
            fields.count { it.type == "Z" } == 1 &&
            fields.count { it.type == "I" } == 1 &&
            fields.count { it.type == "J" } == 1
}

// vipStatus getter: int, no params, not hashCode
internal object AccountVipStatusFingerprint : Fingerprint(
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "I",
    parameters = listOf(),
    custom = { method, classDef ->
        method.implementation != null &&
                method.name != "hashCode" &&
                isAccountDataClass(classDef)
    }
)

// vipDueDate getter: long, no params
internal object AccountVipDueDateFingerprint : Fingerprint(
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "J",
    parameters = listOf(),
    custom = { method, classDef ->
        method.implementation != null && isAccountDataClass(classDef)
    }
)

// ─── HookState isVipUser ────────────────────────────────────────────────────
// HookState-like class: ≥5 List fields, ≥5 String fields, Boolean/boolean, int,
// and a factory method with ≥18 params returning itself.
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

// ─── ProfileState isVipUser ─────────────────────────────────────────────────
// ProfileState (fr4): Set, Map, String, boolean, Boolean, + 1 more = 6 fields
private fun isProfileStateClass(classDef: ClassDef): Boolean {
    val fields = classDef.fields.toList()
    return fields.size == 6 &&
            fields.any { it.type == "Ljava/util/Set;" } &&
            fields.any { it.type == "Ljava/util/Map;" } &&
            fields.any { it.type == "Ljava/lang/String;" } &&
            fields.any { it.type == "Z" } &&
            fields.any { it.type == "Ljava/lang/Boolean;" }
}

internal object ProfileStateVipGetterFingerprint : Fingerprint(
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "Ljava/lang/Boolean;",
    parameters = listOf(),
    custom = { method, classDef ->
        method.implementation != null && isProfileStateClass(classDef)
    }
)

// ─── UserInfo Parcelable (d6) ───────────────────────────────────────────────
// UserInfo: String, int, long, boolean, Parcelable$Creator
private fun isUserInfoClass(classDef: ClassDef): Boolean {
    val fields = classDef.fields.toList()
    return fields.any { it.type == "Ljava/lang/String;" } &&
            fields.any { it.type == "I" } &&
            fields.any { it.type == "J" } &&
            fields.any { it.type == "Z" } &&
            fields.any { it.type == "Landroid/os/Parcelable\$Creator;" }
}

// ─── Signature Bypass (ep5) ─────────────────────────────────────────────────
// ep5.d(Context) → boolean  (APK signature verification)
internal object SignatureVerifierFingerprint : Fingerprint(
    definingClass = "Lkotlin/ep5;",
    returnType = "Z",
    parameters = listOf("Landroid/content/Context;"),
    custom = { method, _ ->
        method.implementation != null && method.parameters.size == 1
    }
)

// ═══════════════════════════════════════════════════════════════════════════
// Patch Implementation
// ═══════════════════════════════════════════════════════════════════════════

val androidFakerVipPatch = bytecodePatch(
    name = "Android Faker VIP unlock",
    description = "Bypasses native tamper detection, forces VIP state everywhere, " +
            "and neuters loadLibrary(\"af_native\") to prevent the anti-tamper kill thread.",
) {
    compatibleWith(COMPATIBILITY_ANDROID_FAKER)

    execute {
        // ─── Helper: replace a native method with a pre-built impl ───────
        fun replaceNativeMethod(
            method: com.android.tools.smali.dexlib2.iface.Method,
            impl: MutableMethodImplementation
        ) {
            val mutableClass = mutableClassDefBy(method.definingClass)

            val replacementMethod = ImmutableMethod(
                method.definingClass,
                method.name,
                method.parameters,
                method.returnType,
                method.accessFlags and AccessFlags.NATIVE.value.inv() and AccessFlags.ABSTRACT.value.inv(),
                method.annotations,
                method.hiddenApiRestrictions,
                impl
            ).toMutable()

            mutableClass.methods.removeAll { candidate ->
                candidate.name == method.name &&
                        candidate.returnType == method.returnType &&
                        candidate.parameterTypes == method.parameterTypes
            }
            mutableClass.methods.add(replacementMethod)
        }

        // ─── 1. Native Anti-Tamper ───────────────────────────────────────
        // doInit(String) → always return true
        NativeDoInitFingerprint.methodOrNull?.let { method ->
            if (method.implementation != null) {
                method.returnEarly(true)
            } else {
                // Build: const/4 v0, 0x1 ; return v0
                val impl = MutableMethodImplementation(2)
                impl.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, 1))
                impl.addInstruction(BuilderInstruction11x(Opcode.RETURN, 0))
                replaceNativeMethod(method, impl)
            }
        }

        // getDex() → return empty byte[] (the UI app doesn't need the spoofing DEX)
        NativeGetDexFingerprint.methodOrNull?.let { method ->
            if (method.implementation != null) {
                val getDexStub = "const/4 v0, 0x0\nnew-array v0, v0, [B\nreturn-object v0"
                method.addInstructions(0, getDexStub)
            } else {
                // Build: const/4 v0, 0x0 ; new-array v0, v0, [B ; return-object v0
                val impl = MutableMethodImplementation(2)
                impl.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, 0))
                impl.addInstruction(
                    BuilderInstruction22c(
                        Opcode.NEW_ARRAY, 0, 0,
                        ImmutableTypeReference("[B")
                    )
                )
                impl.addInstruction(BuilderInstruction11x(Opcode.RETURN_OBJECT, 0))
                replaceNativeMethod(method, impl)
            }
        }

        // ─── 2. Nuke loadLibrary("af_native") calls ─────────────────────
        // Remove all invocations of System.loadLibrary("af_native") across
        // the entire APK so the hostile native library never loads.
        classDefForEach { classDef ->
            classDef.methods.forEach { method ->
                val impl = method.implementation ?: return@forEach
                val instructions = impl.instructions.toList()

                // Look for const-string "af_native" followed by invoke-static System.loadLibrary
                instructions.forEachIndexed { index, instruction ->
                    if (instruction.opcode == Opcode.CONST_STRING &&
                        instruction is Instruction21c &&
                        (instruction.reference as? StringReference)?.string == "af_native"
                    ) {
                        // Check the next instruction is invoke-static {vX}, System.loadLibrary
                        val nextIdx = index + 1
                        if (nextIdx < instructions.size) {
                            val next = instructions[nextIdx]
                            if (next.opcode == Opcode.INVOKE_STATIC &&
                                next is Instruction35c
                            ) {
                                val ref = next.reference as? MethodReference
                                if (ref?.name == "loadLibrary" &&
                                    ref.definingClass == "Ljava/lang/System;"
                                ) {
                                    // NOP both instructions
                                    val mutableClass = mutableClassDefBy(classDef)
                                    val mutableMethod = mutableClass.findMutableMethodOf(method)
                                    mutableMethod.replaceInstruction(index, "nop")
                                    mutableMethod.replaceInstruction(nextIdx, "nop")
                                }
                            }
                        }
                    }
                }
            }
        }

        // ─── 3. Core VIP Check: ms6.b() → true ──────────────────────────
        CoreIsVipFingerprint.methodOrNull?.let { method ->
            method.returnEarly(true)
        }

        // ─── 4. Account Data: vipStatus → 1, vipDueDate → 2100 ──────────
        AccountVipStatusFingerprint.methodOrNull?.let { method ->
            method.returnEarly(1)
        }

        AccountVipDueDateFingerprint.methodOrNull?.let { method ->
            method.addInstructions(
                0,
                """
                    const-wide v0, 0xF4624C00
                    return-wide v0
                """
            )
        }

        // ─── 5. HookState.isVipUser → Boolean.TRUE ──────────────────────
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

        // ─── 6. ProfileState.isVipUser → Boolean.TRUE ────────────────────
        ProfileStateVipGetterFingerprint.methodOrNull?.let { method ->
            method.addInstructions(
                0,
                """
                    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
                    return-object v0
                """
            )
        }

        // ─── 7. UserInfo Parcelable: vipStatus → 1, dueDate → 2100 ──────
        // Scan for UserInfo-like classes using field structure matching
        classDefForEach { classDef ->
            if (!isUserInfoClass(classDef)) return@classDefForEach

            val mutableClass = mutableClassDefBy(classDef)

            mutableClass.methods.forEach { method ->
                if (method.implementation == null) return@forEach

                // int getter (not describeContents/hashCode) → return 1
                if (method.returnType == "I" &&
                    method.parameters.isEmpty() &&
                    method.name != "describeContents" &&
                    method.name != "hashCode" &&
                    method.accessFlags and AccessFlags.PUBLIC.value != 0
                ) {
                    method.returnEarly(1)
                }

                // long getter → return far future epoch
                if (method.returnType == "J" &&
                    method.parameters.isEmpty() &&
                    method.accessFlags and AccessFlags.PUBLIC.value != 0
                ) {
                    method.addInstructions(
                        0,
                        """
                            const-wide v0, 0xF4624C00
                            return-wide v0
                        """
                    )
                }
            }
        }

        // ─── 8. Signature Bypass: ep5.d(Context) → true ─────────────────
        SignatureVerifierFingerprint.methodOrNull?.let { method ->
            method.returnEarly(true)
        }

        // ─── 9. Randomize + ApplyModel VIP params ────────────────────────
        // tg2 methods that take (HookConfig, boolean) and (HookConfig, Model, String, boolean)
        // Force the boolean isVipUser param to true
        val hookConfigType = "Lcom/androidfaker/data/repository/util/HookConfig;"
        classDefForEach { classDef ->
            classDef.methods.forEach { method ->
                val impl = method.implementation ?: return@forEach

                // Randomize: HookConfig method(HookConfig, boolean) → force arg[1] = true
                if (method.returnType == hookConfigType &&
                    method.parameters.size == 2 &&
                    method.parameterTypes[0] == hookConfigType &&
                    method.parameterTypes[1] == "Z"
                ) {
                    val mutableClass = mutableClassDefBy(classDef)
                    val mutableMethod = mutableClass.findMutableMethodOf(method)
                    // Insert at index 0: const/4 p2, 0x1 (force isVipUser = true)
                    mutableMethod.addInstructions(
                        0,
                        "const/4 p2, 0x1"
                    )
                }

                // ApplyModel: HookConfig method(HookConfig, ?, String, boolean)
                if (method.returnType == hookConfigType &&
                    method.parameters.size == 4 &&
                    method.parameterTypes[0] == hookConfigType &&
                    method.parameterTypes[2] == "Ljava/lang/String;" &&
                    method.parameterTypes[3] == "Z"
                ) {
                    val mutableClass = mutableClassDefBy(classDef)
                    val mutableMethod = mutableClass.findMutableMethodOf(method)
                    // Insert at index 0: const/4 p4, 0x1 (force isVipUser = true)
                    mutableMethod.addInstructions(
                        0,
                        "const/4 p4, 0x1"
                    )
                }
            }
        }
    }
}
