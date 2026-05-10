// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-RESILIENCE-3

package ts.sun.tomato_sentinel.security

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.security.MessageDigest

class TamperDetector(private val context: Context) {

    fun isTampered(): Boolean {
        return checkSignature() ||
                checkInstaller() ||
                checkDebuggable()
    }

    private fun checkSignature(): Boolean {
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            if (signatures == null || signatures.isEmpty()) {
                return true
            }

            // In production, compare against known good signature hash
            // For now, just check if signature exists
            false
        } catch (e: Exception) {
            true
        }
    }

    private fun checkInstaller(): Boolean {
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(context.packageName)
        }

        val validInstallers = listOf(
            "com.android.vending",  // Google Play Store
            "com.google.android.feedback",
            "com.android.packageinstaller"
        )

        return installer == null || !validInstallers.contains(installer)
    }

    private fun checkDebuggable(): Boolean {
        return (context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    fun getSignatureHash(): String? {
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

            val signature = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners?.firstOrNull()
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures?.firstOrNull()
            }

            signature?.let {
                val md = MessageDigest.getInstance("SHA-256")
                val digest = md.digest(it.toByteArray())
                digest.joinToString("") { byte -> "%02x".format(byte) }
            }
        } catch (e: Exception) {
            null
        }
    }
}
