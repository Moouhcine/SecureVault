package dz.univ_usto.oss.secure_vault.security

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import java.security.SecureRandom

object IntegrityChecker {
    fun isIntegrityEnforced(context: Context): Boolean {
        return false // Temporarily disabled for testing
        /*
        val hasInternet = context.checkSelfPermission(android.Manifest.permission.INTERNET) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
        if (!hasInternet) return false
        return try {
            context.packageManager.getPackageInfo("com.google.android.gms", 0)
            true
        } catch (_: Exception) {
            false
        }
        */
    }

    fun requestIntegrityToken(
        context: Context,
        onSuccess: () -> Unit,
        onFailure: (Throwable) -> Unit
    ) {
        try {
            val integrityManager = IntegrityManagerFactory.create(context)
            val request = com.google.android.play.core.integrity.IntegrityTokenRequest.builder()
                .setNonce(generateNonce())
                .build()

            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener {
                    // Token must be verified on a backend for a real verdict.
                    onSuccess()
                }
                .addOnFailureListener { error ->
                    onFailure(error)
                }
        } catch (error: Exception) {
            onFailure(error)
        }
    }

    private fun generateNonce(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }
}

