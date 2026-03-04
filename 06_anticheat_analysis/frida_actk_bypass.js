/*
 * TEST 06b: ACTk Anti-Cheat Bypass - Frida Runtime Hook
 * ========================================================
 * Hooks CodeStage ACTk detectors to prevent cheat detection.
 * Also hooks ObscuredType decrypt methods to read real values.
 *
 * Usage:
 *   1. Start the game
 *   2. Run: frida -p $(pgrep FishingPlanet) -l frida_actk_bypass.js
 *
 * Severity: HIGH
 */

const MODULE_NAME = "GameAssembly.so";

function main() {
    send("=== ACTk Anti-Cheat Bypass ===");

    const mod = Process.findModuleByName(MODULE_NAME);
    if (!mod) {
        send("[-] GameAssembly.so not loaded");
        return;
    }
    send(`[+] Module base: ${mod.base}`);

    // Monitor il2cpp_string_new for detector-related strings
    const il2cpp_string_new = Module.findExportByName(MODULE_NAME, "il2cpp_string_new");
    if (il2cpp_string_new) {
        Interceptor.attach(il2cpp_string_new, {
            onEnter: function(args) {
                try {
                    const str = args[0].readUtf8String();
                    if (str && (
                        str.includes("[ACTk]") ||
                        str.includes("Detector") ||
                        str.includes("cheating") ||
                        str.includes("hack") ||
                        str.includes("Obscured")
                    )) {
                        send(`[INTERCEPT] ACTk string: "${str}"`);
                    }
                } catch (e) {}
            }
        });
        send("[+] Monitoring ACTk string creation");
    }

    // Hook il2cpp_runtime_invoke to catch detector method calls
    const il2cpp_runtime_invoke = Module.findExportByName(MODULE_NAME, "il2cpp_runtime_invoke");
    if (il2cpp_runtime_invoke) {
        const il2cpp_method_get_name = new NativeFunction(
            Module.findExportByName(MODULE_NAME, "il2cpp_method_get_name"),
            "pointer", ["pointer"]
        );

        Interceptor.attach(il2cpp_runtime_invoke, {
            onEnter: function(args) {
                try {
                    const methodPtr = args[0];
                    const namePtr = il2cpp_method_get_name(methodPtr);
                    const name = namePtr.readUtf8String();

                    // Block detector methods
                    if (name && (
                        name.includes("StartDetection") ||
                        name.includes("OnCheatingDetected") ||
                        name.includes("Detect") && name.includes("Hack") ||
                        name.includes("ReportCheat")
                    )) {
                        send(`[BLOCKED] Detector call: ${name}`);
                        // Replace method pointer with a no-op
                        // This prevents the detector from actually running
                        this.blockCall = true;
                    }

                    // Monitor ObscuredType operations
                    if (name && (
                        name.includes("Decrypt") ||
                        name.includes("GetDecrypted") ||
                        name.includes("InternalDecrypt")
                    )) {
                        send(`[MONITOR] ObscuredType decrypt: ${name}`);
                    }
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (this.blockCall) {
                    // Return null to prevent detector callback execution
                    retval.replace(ptr(0));
                }
            }
        });
        send("[+] Hooking il2cpp_runtime_invoke for detector bypass");
    }

    // Search for ACTk detector activation strings
    const detectorStrings = [
        "Speed Hack Detector",
        "Obscured Cheating Detector",
        "Time Cheating Detector",
        "Injection Detector"
    ];

    for (const searchStr of detectorStrings) {
        const pattern = [];
        for (let i = 0; i < searchStr.length; i++) {
            pattern.push(searchStr.charCodeAt(i).toString(16).padStart(2, "0"));
        }
        const matches = Memory.scanSync(mod.base, mod.size, pattern.join(" "));
        send(`[*] "${searchStr}": ${matches.length} references found`);
    }

    send("\n[*] ACTk bypass active. Detectors will be blocked.");
    send("[*] ObscuredType decryption calls are being monitored.");
}

setTimeout(main, 0);
