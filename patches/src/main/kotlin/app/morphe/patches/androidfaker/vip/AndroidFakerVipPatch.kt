package app.morphe.patches.androidfaker.vip

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.OpcodesFilter

import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.Compatibility
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patches.shared.misc.hex.hexPatch
import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod.Companion.toMutable
import app.morphe.util.findMutableMethodOf
import app.morphe.util.returnEarly
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21s
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction51l
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableFieldReference
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference

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

// ─── Native Binary Kill-Switch (multi-arch) ─────────────────────────────────
// Patch verified abort-trigger blocks in libaf_native.so so the native kill
// path cannot execute even if the library still gets loaded.
private val androidFakerNativeKillSwitchPatch = hexPatch(ignoreMissingTargetFiles = true, block = {
    "1F 01 09 EB 41 00 00 54 46 2E 00 94 BD 2D 00 94 FF C3 00 D1" asPatternTo
            "1F 01 09 EB 41 00 00 54 1C 00 00 14 BD 2D 00 94 FF C3 00 D1" inFile
            "lib/arm64-v8a/libaf_native.so"

    // x86 (verified unique in current libaf_native.so)
    // cmp [esp+0x14], eax ; jne +5 ; call abort ; call <non-abort helper>
    "00 00 3B 44 24 14 75 05 E8 A6 9F 00 00 E8 71 9D 00 00" asPatternTo
        "00 00 3B 44 24 14 75 05 90 90 90 90 90 E8 71 9D 00 00" inFile
        "lib/x86/libaf_native.so"

    // x86_64 (verified unique in current libaf_native.so)
    // cmp [rsp+0x10], rax ; jne +5 ; call abort ; call <non-abort helper>
    "00 48 3B 44 24 10 75 05 E8 D3 A0 00 00 E8 9E 9E 00 00" asPatternTo
        "00 48 3B 44 24 10 75 05 90 90 90 90 90 E8 9E 9E 00 00" inFile
        "lib/x86_64/libaf_native.so"
})

// ─── Core VIP Check ─────────────────────────────────────────────────────────
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
private fun isAccountDataClass(classDef: ClassDef): Boolean {
    val fields = classDef.fields.toList()
    return fields.size == 5 &&
            fields.count { it.type == "Ljava/lang/String;" } == 2 &&
            fields.count { it.type == "Z" } == 1 &&
            fields.count { it.type == "I" } == 1 &&
            fields.count { it.type == "J" } == 1
}

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

internal object AccountVipDueDateFingerprint : Fingerprint(
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    returnType = "J",
    parameters = listOf(),
    custom = { method, classDef ->
        method.implementation != null && isAccountDataClass(classDef)
    }
)

// ─── HookState isVipUser ────────────────────────────────────────────────────
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
private fun isUserInfoClass(classDef: ClassDef): Boolean {
    val fields = classDef.fields.toList()
    return fields.any { it.type == "Ljava/lang/String;" } &&
            fields.any { it.type == "I" } &&
            fields.any { it.type == "J" } &&
            fields.any { it.type == "Z" } &&
            fields.any { it.type == "Landroid/os/Parcelable\$Creator;" }
}

// ─── Signature Bypass (ep5) ─────────────────────────────────────────────────
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
    description = "Patches native anti-tamper in libaf_native.so while keeping native runtime " +
            "behavior intact, and forces VIP state everywhere.",
) {
    dependsOn(androidFakerNativeKillSwitchPatch)
    compatibleWith(COMPATIBILITY_ANDROID_FAKER)
    extendWith("extensions/androidfaker.mpe")

    execute {
        // ─── Helper: replace a method with a pre-built impl ──────────────
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

        // ─── Helper: create a verifier-safe long-return implementation ─────
        // CONST_WIDE uses two registers. Some tiny getters only expose one
        // register (p0), so we replace method bodies with registerCount >= 3.
        fun buildLongReturnImpl(method: com.android.tools.smali.dexlib2.iface.Method, value: Long): MutableMethodImplementation {
            val originalRegisterCount = method.implementation?.registerCount ?: 0
            val impl = MutableMethodImplementation(maxOf(3, originalRegisterCount))
            impl.addInstruction(BuilderInstruction51l(Opcode.CONST_WIDE, 0, value))
            impl.addInstruction(BuilderInstruction11x(Opcode.RETURN_WIDE, 0))
            return impl
        }

        // ─── 0. JNI-safe native pipeline bridge ──────────────────────────
        // Keep Native.doInit/getDex native so JNI_OnLoad RegisterNatives succeeds.
        // Instead, rewrite Java callsites:
        // - Native.doInit(String): keep invoke for native side-effects, force move-result to 1
        // - Native.getDex(): route invoke to PatchedDexProvider.get()
        val doInitNamesByClass = mutableMapOf<String, Set<String>>()
        val getDexNamesByClass = mutableMapOf<String, Set<String>>()

        classDefForEach { classDef ->
            val hasSingletonInstanceField = classDef.fields.any {
                it.type == classDef.type &&
                        (it.accessFlags and AccessFlags.STATIC.value != 0)
            }

            if (!hasSingletonInstanceField) return@classDefForEach

            val doInitLikeNames = classDef.methods
                .filter {
                            it.returnType == "Z" &&
                            it.parameterTypes.size == 1 &&
                            it.parameterTypes[0] == "Ljava/lang/String;"
                }
                .map { it.name }
                .toSet()

            val getDexLikeNames = classDef.methods
                .filter {
                            it.returnType == "[B" &&
                            it.parameterTypes.isEmpty()
                }
                .map { it.name }
                .toSet()

            if (doInitLikeNames.isNotEmpty() && getDexLikeNames.isNotEmpty()) {
                doInitNamesByClass[classDef.type] = doInitLikeNames
                getDexNamesByClass[classDef.type] = getDexLikeNames
            }
        }

        if (doInitNamesByClass.isEmpty() || getDexNamesByClass.isEmpty()) {
            classDefForEach { classDef ->
                val doInitLikeNames = classDef.methods
                    .filter {
                        it.returnType == "Z" &&
                                it.parameterTypes.size == 1 &&
                                it.parameterTypes[0] == "Ljava/lang/String;"
                    }
                    .map { it.name }
                    .toSet()

                val getDexLikeNames = classDef.methods
                    .filter {
                        it.returnType == "[B" &&
                                it.parameterTypes.isEmpty()
                    }
                    .map { it.name }
                    .toSet()

                if (doInitLikeNames.isNotEmpty() && getDexLikeNames.isNotEmpty()) {
                    doInitNamesByClass.putIfAbsent(classDef.type, doInitLikeNames)
                    getDexNamesByClass.putIfAbsent(classDef.type, getDexLikeNames)
                }
            }
        }

        if (!doInitNamesByClass.containsKey("Lcom/androidfaker/core/util/Native;")) {
            doInitNamesByClass["Lcom/androidfaker/core/util/Native;"] = setOf("doInit")
        }
        if (!getDexNamesByClass.containsKey("Lcom/androidfaker/core/util/Native;")) {
            getDexNamesByClass["Lcom/androidfaker/core/util/Native;"] = setOf("getDex")
        }

        classDefForEach { classDef ->
            val mutableClass = mutableClassDefBy(classDef)

            classDef.methods.forEach methodLoop@{ method ->
                val impl = method.implementation ?: return@methodLoop
                val instructions = impl.instructions.toList()

                val mutableMethod = mutableClass.findMutableMethodOf(method)

                instructions.forEachIndexed { index, insn ->
                    val ref = (insn as? ReferenceInstruction)
                        ?.reference as? MethodReference ?: return@forEachIndexed

                    val targetDoInitNames = doInitNamesByClass[ref.definingClass] ?: emptySet()
                    val targetGetDexNames = getDexNamesByClass[ref.definingClass] ?: emptySet()

                    val isNativeDoInitCall =
                        (
                            insn.opcode == Opcode.INVOKE_VIRTUAL ||
                                insn.opcode == Opcode.INVOKE_VIRTUAL_RANGE ||
                                insn.opcode == Opcode.INVOKE_DIRECT ||
                                insn.opcode == Opcode.INVOKE_DIRECT_RANGE ||
                                insn.opcode == Opcode.INVOKE_STATIC ||
                                insn.opcode == Opcode.INVOKE_STATIC_RANGE
                            ) &&
                                targetDoInitNames.contains(ref.name) &&
                                ref.returnType == "Z" &&
                                ref.parameterTypes.size == 1 &&
                                ref.parameterTypes[0] == "Ljava/lang/String;"

                    if (isNativeDoInitCall) {
                        val nextInsn = instructions.getOrNull(index + 1)
                        if (nextInsn?.opcode == Opcode.MOVE_RESULT) {
                            val resultRegister = (nextInsn as OneRegisterInstruction).registerA
                            mutableMethod.implementation!!.replaceInstruction(
                                index + 1,
                                BuilderInstruction21s(Opcode.CONST_16, resultRegister, 1)
                            )
                        }
                        return@forEachIndexed
                    }

                    val isNativeGetDexCall =
                        (
                            insn.opcode == Opcode.INVOKE_VIRTUAL ||
                                insn.opcode == Opcode.INVOKE_VIRTUAL_RANGE ||
                                insn.opcode == Opcode.INVOKE_DIRECT ||
                                insn.opcode == Opcode.INVOKE_DIRECT_RANGE ||
                                insn.opcode == Opcode.INVOKE_STATIC ||
                                insn.opcode == Opcode.INVOKE_STATIC_RANGE
                            ) &&
                                targetGetDexNames.contains(ref.name) &&
                                ref.returnType == "[B" &&
                                ref.parameterTypes.isEmpty()

                    if (isNativeGetDexCall) {
                        mutableMethod.implementation!!.replaceInstruction(
                            index,
                            BuilderInstruction35c(
                                Opcode.INVOKE_STATIC,
                                0, 0, 0, 0, 0, 0,
                                ImmutableMethodReference(
                                    "Lapp/morphe/extension/androidfaker/PatchedDexProvider;",
                                    "get",
                                    emptyList(),
                                    "[B"
                                )
                            )
                        )
                    }
                }
            }
        }

        // ─── 1. Core VIP Check: ms6.b() → true ──────────────────────────
        CoreIsVipFingerprint.methodOrNull?.let { method ->
            method.returnEarly(true)
        }

        // ─── 2. Account Data: vipStatus → 1, vipDueDate → far future ────
        AccountVipStatusFingerprint.methodOrNull?.let { method ->
            method.returnEarly(1)
        }

        AccountVipDueDateFingerprint.methodOrNull?.let { method ->
            replaceNativeMethod(method, buildLongReturnImpl(method, 4102444800L))
        }

        // ─── 3. HookState.isVipUser → Boolean.TRUE ──────────────────────
        val vipGetterObject = HookStateVipGetterFingerprint.methodOrNull
        if (vipGetterObject?.implementation != null) {
            // Insert in reverse: SGET_OBJECT v0, Boolean.TRUE ; RETURN_OBJECT v0
            vipGetterObject.implementation!!.addInstruction(0,
                BuilderInstruction11x(Opcode.RETURN_OBJECT, 0))
            vipGetterObject.implementation!!.addInstruction(0,
                BuilderInstruction21c(
                    Opcode.SGET_OBJECT, 0,
                    ImmutableFieldReference("Ljava/lang/Boolean;", "TRUE", "Ljava/lang/Boolean;")
                ))
        } else if (HookStateVipGetterPrimitiveFingerprint.methodOrNull?.implementation != null) {
            HookStateVipGetterPrimitiveFingerprint.method.returnEarly(true)
        }

        // ─── 4. ProfileState.isVipUser → Boolean.TRUE ────────────────────
        ProfileStateVipGetterFingerprint.methodOrNull?.let { method ->
            method.implementation!!.addInstruction(0,
                BuilderInstruction11x(Opcode.RETURN_OBJECT, 0))
            method.implementation!!.addInstruction(0,
                BuilderInstruction21c(
                    Opcode.SGET_OBJECT, 0,
                    ImmutableFieldReference("Ljava/lang/Boolean;", "TRUE", "Ljava/lang/Boolean;")
                ))
        }

        // ─── 5. UserInfo Parcelable: vipStatus → 1, dueDate → 2100 ──────
        classDefForEach { classDef ->
            if (!isUserInfoClass(classDef)) return@classDefForEach

            val mutableClass = mutableClassDefBy(classDef)

            mutableClass.methods.toList().forEach { method ->
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
                    replaceNativeMethod(method, buildLongReturnImpl(method, 4102444800L))
                }
            }
        }

        // ─── 6. Signature Bypass: ep5.d(Context) → true ─────────────────
        SignatureVerifierFingerprint.methodOrNull?.let { method ->
            method.returnEarly(true)
        }

        // ─── 7. Randomize + ApplyModel VIP params ────────────────────────
        val hookConfigType = "Lcom/androidfaker/data/repository/util/HookConfig;"
        classDefForEach { classDef ->
            classDef.methods.forEach { method ->
                val impl = method.implementation ?: return@forEach

                // Randomize: method(HookConfig, boolean) → force isVipUser = true
                if (method.returnType == hookConfigType &&
                    method.parameters.size == 2 &&
                    method.parameterTypes[0] == hookConfigType &&
                    method.parameterTypes[1] == "Z"
                ) {
                    val mutableClass = mutableClassDefBy(classDef)
                    val mutableMethod = mutableClass.findMutableMethodOf(method)
                    val boolReg = mutableMethod.implementation!!.registerCount - 1
                    mutableMethod.implementation!!.addInstruction(0,
                        BuilderInstruction21s(Opcode.CONST_16, boolReg, 1))
                }

                // ApplyModel: method(HookConfig, ?, String, boolean) → force isVipUser = true
                if (method.returnType == hookConfigType &&
                    method.parameters.size == 4 &&
                    method.parameterTypes[0] == hookConfigType &&
                    method.parameterTypes[2] == "Ljava/lang/String;" &&
                    method.parameterTypes[3] == "Z"
                ) {
                    val mutableClass = mutableClassDefBy(classDef)
                    val mutableMethod = mutableClass.findMutableMethodOf(method)
                    val boolReg = mutableMethod.implementation!!.registerCount - 1
                    mutableMethod.implementation!!.addInstruction(0,
                        BuilderInstruction21s(Opcode.CONST_16, boolReg, 1))
                }
            }
        }
    }
}
