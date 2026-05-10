// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-RESILIENCE-5

package ts.sun.tomato_sentinel.security

import android.content.Context
import android.os.Build
import android.provider.Settings

class EmulatorDetector(private val context: Context) {

    fun isEmulator(): Boolean {
        return checkBasicEmulatorProperties() ||
                checkAdvancedEmulatorProperties() ||
                checkEmulatorFiles() ||
                checkOperatorName() ||
                checkDeviceId()
    }

    private fun checkBasicEmulatorProperties(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for x86") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic") ||
                "google_sdk" == Build.PRODUCT)
    }

    private fun checkAdvancedEmulatorProperties(): Boolean {
        return (Build.BOARD == "unknown" ||
                Build.BOOTLOADER == "unknown" ||
                Build.BRAND == "generic" ||
                Build.DEVICE == "generic" ||
                Build.HARDWARE.contains("goldfish") ||
                Build.HARDWARE.contains("ranchu") ||
                Build.HOST.startsWith("Build") ||
                Build.ID.startsWith("FRF91") ||
                Build.MANUFACTURER == "unknown" ||
                Build.MODEL == "sdk" ||
                Build.PRODUCT == "sdk" ||
                Build.TAGS.contains("test-keys") ||
                Build.TYPE == "eng" ||
                Build.USER == "android-build")
    }

    private fun checkEmulatorFiles(): Boolean {
        val emulatorFiles = arrayOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
        )
        return emulatorFiles.any { java.io.File(it).exists() }
    }

    private fun checkOperatorName(): Boolean {
        val operatorName = android.telephony.TelephonyManager::class.java
            .let { context.getSystemService(Context.TELEPHONY_SERVICE) as android.telephony.TelephonyManager }
            .networkOperatorName
        return operatorName.lowercase() == "android"
    }

    private fun checkDeviceId(): Boolean {
        val deviceId = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ANDROID_ID
        )
        return deviceId == null || deviceId == "9774d56d682e549c"
    }
}
