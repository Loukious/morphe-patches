package app.morphe.patches.androidfaker.vip

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.OpcodesFilter

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
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21s
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction51l
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableFieldReference
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

// ─── Native Anti-Tamper ─────────────────────────────────────────────────────
internal object NativeDoInitFingerprint : Fingerprint(
    definingClass = "Lcom/androidfaker/core/util/Native;",
    name = "doInit",
    returnType = "Z",
    parameters = listOf("Ljava/lang/String;"),
    custom = { method, _ -> method.parameters.size == 1 }
)

internal object NativeGetDexFingerprint : Fingerprint(
    definingClass = "Lcom/androidfaker/core/util/Native;",
    name = "getDex",
    returnType = "[B",
    parameters = listOf()
)

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
    description = "Bypasses native tamper detection, forces VIP state everywhere, " +
            "and neuters all loadLibrary(\"af_native\") calls to prevent the anti-tamper kill threads.",
) {
    compatibleWith(COMPATIBILITY_ANDROID_FAKER)
    extendWith("extensions/androidfaker.mpe")

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

        // ─── Helper: ensure wide instructions have enough registers ──────
        // CONST_WIDE needs v0+v1 (2 local registers). A simple getter often
        // only has p0 (this) as registerCount=1, so we bump to 3:
        //   v0, v1 = wide locals; v2 = p0 (this)
        fun ensureWideRegisters(impl: MutableMethodImplementation) {
            if (impl.registerCount < 2) {
                // registerCount = locals + params. We need at least 2 locals.
                // Add 2 to make room for the wide pair, keeping params at end.
                impl.registerCount = impl.registerCount + 2
            }
        }

        // ─── 1. Native Anti-Tamper ───────────────────────────────────────
        // doInit(String) → always return true
        NativeDoInitFingerprint.methodOrNull?.let { method ->
            if (method.implementation != null) {
                method.returnEarly(true)
            } else {
                val impl = MutableMethodImplementation(2)
                impl.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, 1))
                impl.addInstruction(BuilderInstruction11x(Opcode.RETURN, 0))
                replaceNativeMethod(method, impl)
            }
        }

        // getDex() → delegate to extension runtime extractor
        NativeGetDexFingerprint.methodOrNull?.let { method ->
            val impl = MutableMethodImplementation(2)
            impl.addInstruction(
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
            impl.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0))
            impl.addInstruction(BuilderInstruction11x(Opcode.RETURN_OBJECT, 0))
            replaceNativeMethod(method, impl)
        }

        // ─── 2. Nuke ALL System.loadLibrary / System.load for af_native ──
        //
        // The .so spawns 7 kill threads in doInit() — these scan for tampering
        // and abort the process. We must prevent the library from loading at all.
        //
        // TWO patterns to catch:
        //   A) Dynamic (obfuscated name): decryptor() → move-result-object vX
        //                                 → System.loadLibrary(vX)
        //   B) Literal:                   const-string vX, "af_native"
        //                                 → System.loadLibrary(vX)
        //
        // Pattern A: NOP only the loadLibrary call (the decryptor result is
        //            likely used only here, so leaving its call is safe, but
        //            NOP'ing is simpler and the unused result is harmless).
        // Pattern B: NOP only the loadLibrary call; the const-string is left
        //            as a dead assignment — the verifier is fine with that.
        //
        // We intentionally leave literal loads of other libraries (mmkv,
        // dexkit, perfetto, etc.) untouched.
        classDefForEach { classDef ->
            classDef.methods.forEach methodLoop@{ method ->
                val impl = method.implementation ?: return@methodLoop
                val instructions = impl.instructions.toList()

                val indicesToNop = mutableListOf<Int>()

                instructions.forEachIndexed { index, insn ->
                    // Must be a System.loadLibrary or System.load call
                    val ref = (insn as? ReferenceInstruction)
                        ?.reference as? MethodReference ?: return@forEachIndexed

                    val isSystemLoad =
                        (insn.opcode == Opcode.INVOKE_STATIC || insn.opcode == Opcode.INVOKE_STATIC_RANGE) &&
                                ref.definingClass == "Ljava/lang/System;" &&
                                (ref.name == "loadLibrary" || ref.name == "load")
                    val isRuntimeLoad =
                        (insn.opcode == Opcode.INVOKE_VIRTUAL || insn.opcode == Opcode.INVOKE_VIRTUAL_RANGE) &&
                                ref.definingClass == "Ljava/lang/Runtime;" &&
                                (ref.name == "loadLibrary" || ref.name == "load")

                    if (!isSystemLoad && !isRuntimeLoad) return@forEachIndexed

                    val prevInsn = instructions.getOrNull(index - 1)
                    val prevOpcode = prevInsn?.opcode

                    // Pattern A: name computed at runtime
                    val isDynamic = prevOpcode == Opcode.MOVE_RESULT_OBJECT

                    // Pattern B: literal "af_native"
                    val isAfNativeLiteral = (prevOpcode == Opcode.CONST_STRING ||
                            prevOpcode == Opcode.CONST_STRING_JUMBO) &&
                            ((prevInsn as? ReferenceInstruction)
                                ?.reference as? StringReference)
                                ?.string == "af_native"

                    if (isDynamic || isAfNativeLiteral) {
                        // NOP the loadLibrary call itself.
                        // Leave the preceding instruction — a dead register write
                        // is harmless and keeps the instruction list indices stable.
                        indicesToNop.add(index)
                    }
                }

                if (indicesToNop.isNotEmpty()) {
                    val mutableClass = mutableClassDefBy(classDef)
                    val mutableMethod = mutableClass.findMutableMethodOf(method)
                    indicesToNop.forEach { idx ->
                        mutableMethod.implementation!!.replaceInstruction(
                            idx, BuilderInstruction10x(Opcode.NOP)
                        )
                    }
                }
            }
        }

        // ─── 3. Core VIP Check: ms6.b() → true ──────────────────────────
        CoreIsVipFingerprint.methodOrNull?.let { method ->
            method.returnEarly(true)
        }

        // ─── 4. Account Data: vipStatus → 1, vipDueDate → far future ────
        AccountVipStatusFingerprint.methodOrNull?.let { method ->
            method.returnEarly(1)
        }

        AccountVipDueDateFingerprint.methodOrNull?.let { method ->
            val impl = method.implementation!!
            // BUG FIX: CONST_WIDE occupies two consecutive registers (vN, vN+1).
            // A plain getter with only `this` has registerCount=1 (p0=v0).
            // Bumping to 3 gives v0+v1 as locals and v2=p0, satisfying the verifier.
            ensureWideRegisters(impl)
            // Insert in reverse order so final order is: CONST_WIDE v0 ; RETURN_WIDE v0
            impl.addInstruction(0, BuilderInstruction11x(Opcode.RETURN_WIDE, 0))
            impl.addInstruction(0, BuilderInstruction51l(Opcode.CONST_WIDE, 0, 4102444800L))
        }

        // ─── 5. HookState.isVipUser → Boolean.TRUE ──────────────────────
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

        // ─── 6. ProfileState.isVipUser → Boolean.TRUE ────────────────────
        ProfileStateVipGetterFingerprint.methodOrNull?.let { method ->
            method.implementation!!.addInstruction(0,
                BuilderInstruction11x(Opcode.RETURN_OBJECT, 0))
            method.implementation!!.addInstruction(0,
                BuilderInstruction21c(
                    Opcode.SGET_OBJECT, 0,
                    ImmutableFieldReference("Ljava/lang/Boolean;", "TRUE", "Ljava/lang/Boolean;")
                ))
        }

        // ─── 7. UserInfo Parcelable: vipStatus → 1, dueDate → 2100 ──────
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
                // BUG FIX: ensure 2 local registers before inserting CONST_WIDE
                if (method.returnType == "J" &&
                    method.parameters.isEmpty() &&
                    method.accessFlags and AccessFlags.PUBLIC.value != 0
                ) {
                    ensureWideRegisters(method.implementation!!)
                    // Insert in reverse: CONST_WIDE v0 ; RETURN_WIDE v0
                    method.implementation!!.addInstruction(0,
                        BuilderInstruction11x(Opcode.RETURN_WIDE, 0))
                    method.implementation!!.addInstruction(0,
                        BuilderInstruction51l(Opcode.CONST_WIDE, 0, 4102444800L))
                }
            }
        }

        // ─── 8. Signature Bypass: ep5.d(Context) → true ─────────────────
        SignatureVerifierFingerprint.methodOrNull?.let { method ->
            method.returnEarly(true)
        }

        // ─── 9. Randomize + ApplyModel VIP params ────────────────────────
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
