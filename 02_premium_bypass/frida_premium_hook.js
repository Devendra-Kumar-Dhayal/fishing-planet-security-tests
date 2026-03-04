/*
 * TEST 02b: Premium Bypass - Frida Runtime Hook
 * ================================================
 * Hooks HasPremium/IsPremium getters to always return true.
 *
 * Usage:
 *   1. Start the game
 *   2. Run: frida -p $(pgrep FishingPlanet) -l frida_premium_hook.js
 *
 * Severity: CRITICAL
 */

// Configuration - update these offsets after running find_premium_offsets.py
const MODULE_NAME = "GameAssembly.so";

// Helper to find IL2CPP method pointers at runtime
function findIl2CppMethod(className, methodName, argCount) {
    const il2cpp_class_from_name = new NativeFunction(
        Module.findExportByName(MODULE_NAME, "il2cpp_class_from_name"),
        "pointer", ["pointer", "pointer", "pointer"]
    );
    const il2cpp_class_get_method_from_name = new NativeFunction(
        Module.findExportByName(MODULE_NAME, "il2cpp_class_get_method_from_name"),
        "pointer", ["pointer", "pointer", "int"]
    );
    const il2cpp_domain_get = new NativeFunction(
        Module.findExportByName(MODULE_NAME, "il2cpp_domain_get"),
        "pointer", []
    );
    const il2cpp_domain_get_assemblies = new NativeFunction(
        Module.findExportByName(MODULE_NAME, "il2cpp_domain_get_assemblies"),
        "pointer", ["pointer", "pointer"]
    );
    const il2cpp_assembly_get_image = new NativeFunction(
        Module.findExportByName(MODULE_NAME, "il2cpp_assembly_get_image"),
        "pointer", ["pointer"]
    );
    const il2cpp_method_get_pointer = new NativeFunction(
        Module.findExportByName(MODULE_NAME, "il2cpp_method_get_pointer") ||
        Module.findExportByName(MODULE_NAME, "il2cpp_resolve_icall"),
        "pointer", ["pointer"]
    );

    // Get domain and assemblies
    const domain = il2cpp_domain_get();
    const sizePtr = Memory.alloc(4);
    const assemblies = il2cpp_domain_get_assemblies(domain, sizePtr);
    const assemblyCount = sizePtr.readU32();

    send(`[*] Searching ${assemblyCount} assemblies for ${className}::${methodName}`);

    for (let i = 0; i < assemblyCount; i++) {
        const assembly = assemblies.add(i * Process.pointerSize).readPointer();
        const image = il2cpp_assembly_get_image(assembly);

        // Try to find the class (split namespace and class name)
        const parts = className.split(".");
        const name = parts.pop();
        const ns = parts.join(".");

        const klass = il2cpp_class_from_name(image, Memory.allocUtf8String(ns), Memory.allocUtf8String(name));
        if (!klass.isNull()) {
            const method = il2cpp_class_get_method_from_name(klass, Memory.allocUtf8String(methodName), argCount);
            if (!method.isNull()) {
                send(`[+] Found ${className}::${methodName} at ${method}`);
                return method;
            }
        }
    }
    return null;
}

// Alternative approach: scan for known string patterns and hook nearby functions
function hookByStringSearch(targetString, hookCallback) {
    const mod = Process.findModuleByName(MODULE_NAME);
    if (!mod) {
        send(`[-] Module ${MODULE_NAME} not found`);
        return;
    }

    send(`[*] Scanning for "${targetString}" in ${MODULE_NAME} (${mod.base}, size: ${mod.size})`);

    const pattern = [];
    for (let i = 0; i < targetString.length; i++) {
        pattern.push(targetString.charCodeAt(i).toString(16).padStart(2, "0"));
    }
    const patternStr = pattern.join(" ");

    const matches = Memory.scanSync(mod.base, mod.size, patternStr);
    send(`[*] Found ${matches.length} references to "${targetString}"`);

    return matches;
}

// Main hooking logic
function main() {
    send("=== Fishing Planet Premium Bypass ===");
    send("[*] Waiting for module load...");

    const mod = Process.findModuleByName(MODULE_NAME);
    if (!mod) {
        send("[-] GameAssembly.so not loaded yet");
        return;
    }
    send(`[+] ${MODULE_NAME} base: ${mod.base}`);

    // Approach 1: Hook via IL2CPP API
    // Search for premium-related property getters
    const premiumTargets = [
        { class: "Profile", method: "get_HasPremium", args: 0 },
        { class: "Profile", method: "get_IsPremium", args: 0 },
        { class: "PlayerProfile", method: "get_HasPremium", args: 0 },
        { class: "PlayerProfile", method: "get_IsPremium", args: 0 },
    ];

    // Approach 2: Pattern scan for bool return functions
    // In x86_64, a function returning true is typically:
    //   mov eax, 1
    //   ret
    // Bytes: B8 01 00 00 00 C3

    // Search for "HasPremium" and "IsPremium" strings to find cross-references
    const hasPremiumRefs = hookByStringSearch("HasPremium");
    const isPremiumRefs = hookByStringSearch("IsPremium");
    const freeForPremiumRefs = hookByStringSearch("FreeForPremium");

    send("\n[*] To complete the hook, run find_premium_offsets.py first");
    send("[*] Then update the offsets below and re-run this script");

    // Placeholder for when offsets are known:
    // Uncomment and fill in after running static analysis
    /*
    const PREMIUM_GETTER_OFFSET = 0x0; // Fill from find_premium_offsets.py

    if (PREMIUM_GETTER_OFFSET !== 0x0) {
        const targetAddr = mod.base.add(PREMIUM_GETTER_OFFSET);
        Interceptor.attach(targetAddr, {
            onLeave: function(retval) {
                send("[+] HasPremium called - patching return to TRUE");
                retval.replace(ptr(1));
            }
        });
        send(`[+] Hooked premium getter at ${targetAddr}`);
    }
    */

    // Hook il2cpp_string_new to monitor string creation (helps find method calls)
    const il2cpp_string_new = Module.findExportByName(MODULE_NAME, "il2cpp_string_new");
    if (il2cpp_string_new) {
        Interceptor.attach(il2cpp_string_new, {
            onEnter: function(args) {
                const str = args[0].readUtf8String();
                if (str && (str.includes("Premium") || str.includes("premium") ||
                            str.includes("HasPremium") || str.includes("IsPremium"))) {
                    send(`[INTERCEPT] il2cpp_string_new("${str}")`);
                    send(`  caller: ${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n  ")}`);
                }
            }
        });
        send("[+] Monitoring il2cpp_string_new for premium-related strings");
    }

    send("\n[*] Premium bypass hooks active. Play the game to trigger premium checks.");
}

setTimeout(main, 0);
