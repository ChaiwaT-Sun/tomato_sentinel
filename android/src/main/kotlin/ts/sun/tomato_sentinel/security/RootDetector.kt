// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-RESILIENCE-1
// Root detection implementation

package ts.sun.tomato_sentinel.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

/**
 * Root Detection
 * 
 * Detects if device is rooted using multiple techniques:
 * - Check for su binary
 * - Check for root management apps
 * - Check for dangerous system properties
 * - Check for RW system partition
 * - Check for Magisk/SuperSU
 */
class RootDetector(private val context: Context) {

    companion object {
        // Known root binaries
        private val SU_PATHS = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )

        // Known root management apps
        private val ROOT_APPS_PACKAGES = arrayOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot"
        )

        // Dangerous system properties
        private val DANGEROUS_PROPS = mapOf(
            "[ro.debuggable]" to "[1]",
            "[ro.secure]" to "[0]"
        )
    }

    /**
     * Check if device is rooted
     * Uses multiple detection methods for higher accuracy
     */
    fun isDeviceRooted(): Boolean {
        return checkRootBinaries() ||
                checkRootApps() ||
                checkDangerousProps() ||
                checkRWPaths() ||
                checkSuExists() ||
                checkMagiskHide()
    }

    /**
     * Check for su binary in common locations
     */
    private fun checkRootBinaries(): Boolean {
        return SU_PATHS.any { path ->
            try {
                File(path).exists()
            } catch (e: Exception) {
                false
            }
        }
    }

    /**
     * Check for root management apps
     */
    private fun checkRootApps(): Boolean {
        val packageManager = context.packageManager
        return ROOT_APPS_PACKAGES.any { packageName ->
            try {
                packageManager.getPackageInfo(packageName, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }

    /**
     * Check for dangerous system properties
     */
    private fun checkDangerousProps(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("getprop")
            val properties = process.inputStream.bufferedReader().readText()
            
            DANGEROUS_PROPS.any { (key, value) ->
                properties.contains(key) && properties.contains(value)
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if system partition is mounted as RW
     */
    private fun checkRWPaths(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("mount")
            val mountInfo = process.inputStream.bufferedReader().readText()
            
            mountInfo.contains("/system") && mountInfo.contains("rw")
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if su command is accessible
     */
    private fun checkSuExists(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val result = process.inputStream.bufferedReader().readText()
            result.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check for Magisk Hide
     * Magisk can hide root, but leaves traces
     */
    private fun checkMagiskHide(): Boolean {
        return try {
            // Check for Magisk mount points
            val process = Runtime.getRuntime().exec("mount")
            val mountInfo = process.inputStream.bufferedReader().readText()
            
            mountInfo.contains("magisk") || mountInfo.contains("/sbin/.magisk")
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check for test-keys (unofficial ROM)
     */
    fun isTestKeyBuild(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }
}
