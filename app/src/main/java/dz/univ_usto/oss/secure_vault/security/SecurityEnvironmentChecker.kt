package dz.univ_usto.oss.secure_vault.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Debug
import android.provider.Settings
import java.io.File

object SecurityEnvironmentChecker {
    const val SECURITY_BYPASS = false 
    /**
     * Checks if the device is rooted by looking for common binaries and APKs.
     */
    fun isDeviceRooted(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu"
        )
        for (path in paths) {
            if (File(path).exists()) return true
        }
        
        // Check for test-keys (usually present on custom ROMs)
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    /**
     * Checks if a debugger is attached to the process.
     */
    fun isDebuggerConnected(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    /**
     * Checks if ADB (Developer Mode) is enabled.
     * In a high-security vault, we might want to block access if ADB is active.
     */
    fun isAdbEnabled(context: Context): Boolean {
        return Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
    }

    /**
     * Checks if developer options are enabled (often paired with ADB/debug settings).
     */
    fun isDeveloperOptionsEnabled(context: Context): Boolean {
        return Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0
    }

    /**
     * Checks for debuggable builds at runtime.
     */
    fun isAppDebuggable(context: Context): Boolean {
        return (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    /**
     * Best-effort detection of common hooking frameworks (Frida/Xposed/LSPosed/Substrate).
     */
    fun isHookingDetected(context: Context): Boolean {
        val suspiciousFiles = listOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server",
            "/system/lib/libsubstrate.so",
            "/system/lib64/libsubstrate.so"
        )
        if (suspiciousFiles.any { File(it).exists() }) return true

        val suspiciousPackages = listOf(
            "com.topjohnwu.magisk",
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "me.weishu.exp",
            "com.saurik.substrate"
        )
        if (isAnyPackageInstalled(context, suspiciousPackages)) return true

        return isProcessMapsSuspicious(
            listOf("frida", "gum-js-loop", "gadget", "xposed", "substrate", "lsposed")
        )
    }

    private fun isAnyPackageInstalled(context: Context, packageNames: List<String>): Boolean {
        val pm = context.packageManager
        return packageNames.any { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (_: Exception) {
                false
            }
        }
    }

    private fun isProcessMapsSuspicious(signatures: List<String>): Boolean {
        return try {
            val maps = File("/proc/self/maps").readText()
            signatures.any { maps.contains(it, ignoreCase = true) }
        } catch (_: Exception) {
            false
        }
    }

    private fun isTracedByDebugger(): Boolean {
        return try {
            val status = File("/proc/self/status").readLines()
            val tracerLine = status.firstOrNull { it.startsWith("TracerPid:") } ?: return false
            val tracerPid = tracerLine.split(":").getOrNull(1)?.trim()?.toIntOrNull() ?: 0
            tracerPid != 0
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Overall security check. Returns true if the environment is safe.
     */
    fun isEnvironmentSafe(context: Context): Boolean {
        if (SECURITY_BYPASS) return true
         return !isDeviceRooted() &&
             !isDebuggerConnected() &&
             (!isAdbEnabled(context)) &&
             !isDeveloperOptionsEnabled(context) &&
             !isAppDebuggable(context) &&
             !isHookingDetected(context) &&
             !isTracedByDebugger()
     }
}
