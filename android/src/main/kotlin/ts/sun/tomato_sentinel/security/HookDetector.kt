// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-RESILIENCE-4

package ts.sun.tomato_sentinel.security

import android.content.Context
import android.content.pm.PackageManager
import java.io.File

class HookDetector(private val context: Context) {

    companion object {
        private val HOOK_FRAMEWORKS = arrayOf(
            "com.saurik.substrate",
            "de.robv.android.xposed.installer",
            "de.robv.android.xposed",
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.noshufou.android.su"
        )

        private val FRIDA_LIBRARIES = arrayOf(
            "frida-agent",
            "frida-gadget",
            "frida-server"
        )

        private val HOOK_PATHS = arrayOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/system/lib/libfrida-gadget.so",
            "/system/lib64/libfrida-gadget.so",
            "/system/xbin/frida-server"
        )
    }

    fun isHooked(): Boolean {
        return checkHookFrameworks() ||
                checkFridaServer() ||
                checkFridaLibraries() ||
                checkXposedBridge() ||
                checkSubstrateFiles()
    }

    private fun checkHookFrameworks(): Boolean {
        val packageManager = context.packageManager
        return HOOK_FRAMEWORKS.any { packageName ->
            try {
                packageManager.getPackageInfo(packageName, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }

    private fun checkFridaServer(): Boolean {
        return HOOK_PATHS.any { path ->
            try {
                File(path).exists()
            } catch (e: Exception) {
                false
            }
        }
    }

    private fun checkFridaLibraries(): Boolean {
        return try {
            val mapsFile = File("/proc/self/maps")
            if (mapsFile.exists()) {
                val maps = mapsFile.readText()
                FRIDA_LIBRARIES.any { lib -> maps.contains(lib) }
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun checkXposedBridge(): Boolean {
        return try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            true
        } catch (e: ClassNotFoundException) {
            false
        }
    }

    private fun checkSubstrateFiles(): Boolean {
        val substrateFiles = arrayOf(
            "/system/lib/libsubstrate.so",
            "/system/lib64/libsubstrate.so",
            "/data/app/com.saurik.substrate"
        )
        return substrateFiles.any { File(it).exists() }
    }

    fun checkDebuggerAttached(): Boolean {
        return android.os.Debug.isDebuggerConnected() ||
                android.os.Debug.waitingForDebugger()
    }
}
