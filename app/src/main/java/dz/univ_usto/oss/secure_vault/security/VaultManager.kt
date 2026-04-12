package dz.univ_usto.oss.secure_vault.security

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.core.content.edit
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.util.Arrays

class VaultManager(context: Context) {
    data class Credential(val title: String, val username: String, val email: String, val password: String)

    private val credentialPrefix = "cred:"

    private val masterKey = try {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .setRequestStrongBoxBacked(true)
            .build()
    } catch (_: Exception) {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    private val sharedPreferences = try {
        EncryptedSharedPreferences.create(
            context,
            "secure_vault_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    } catch (e: Exception) {
        // Fallback: If the keyset is corrupted, we must recreate it.
        // In a real production app, this would mean data loss, but it's better than a crash.
        context.deleteSharedPreferences("secure_vault_prefs")
        EncryptedSharedPreferences.create(
            context,
            "secure_vault_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun saveCredential(title: String, username: CharArray, email: CharArray, password: CharArray) {
        val keyId = encodeKey(title)
        val userString = username.concatToString()
        val emailString = email.concatToString()
        val passString = password.concatToString()
        sharedPreferences.edit {
            putString("$credentialPrefix$keyId:username", userString)
            putString("$credentialPrefix$keyId:email", emailString)
            putString("$credentialPrefix$keyId:password", passString)
            putString("$credentialPrefix$keyId:title", title)
        }
        Arrays.fill(username, '\u0000')
        Arrays.fill(email, '\u0000')
        Arrays.fill(password, '\u0000')
    }

    fun getCredential(title: String): Credential? {
        val keyId = encodeKey(title)
        val username = sharedPreferences.getString("$credentialPrefix$keyId:username", null) ?: return null
        val password = sharedPreferences.getString("$credentialPrefix$keyId:password", null) ?: return null
        val email = sharedPreferences.getString("$credentialPrefix$keyId:email", "") ?: ""
        val storedTitle = sharedPreferences.getString("$credentialPrefix$keyId:title", title) ?: title
        return Credential(storedTitle, username, email, password)
    }

    fun getAllCredentialTitles(): List<String> {
        return sharedPreferences.all.keys
            .filter { it.startsWith(credentialPrefix) && it.endsWith(":title") }
            .mapNotNull { sharedPreferences.getString(it, null) }
            .sorted()
    }

    fun getAllCredentials(): List<Credential> {
        return getAllCredentialTitles().mapNotNull { getCredential(it) }
    }


    fun deleteCredential(title: String) {
        val keyId = encodeKey(title)
        sharedPreferences.edit {
            remove("$credentialPrefix$keyId:username")
            remove("$credentialPrefix$keyId:email")
            remove("$credentialPrefix$keyId:password")
            remove("$credentialPrefix$keyId:title")
        }
    }


    private fun encodeKey(value: String): String {
        return Base64.encodeToString(value.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
    }
}
