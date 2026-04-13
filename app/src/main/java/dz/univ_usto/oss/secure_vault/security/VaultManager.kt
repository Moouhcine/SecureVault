package dz.univ_usto.oss.secure_vault.security

import android.content.Context
import android.util.Base64
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.Arrays
import javax.crypto.Cipher

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

    private val sharedPreferences = EncryptedSharedPreferences.create(
        context,
        "secure_vault_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveCredential(title: String, username: CharArray, email: CharArray, password: CharArray, cipher: Cipher) {
        val keyId = encodeKey(title)
        
        // Serialization in a single block to avoid IV reuse error in GCM
        val u = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(username))
        val e = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(email))
        val p = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(password))

        val combined = ByteBuffer.allocate(4 + u.limit() + 4 + e.limit() + 4 + p.limit())
        combined.putInt(u.limit()); combined.put(u)
        combined.putInt(e.limit()); combined.put(e)
        combined.putInt(p.limit()); combined.put(p)

        val encryptedBlob = cipher.doFinal(combined.array())
        val ivString = Base64.encodeToString(cipher.iv, Base64.NO_WRAP)

        sharedPreferences.edit {
            putString("$credentialPrefix$keyId:data", Base64.encodeToString(encryptedBlob, Base64.NO_WRAP))
            putString("$credentialPrefix$keyId:iv", ivString)
            putString("$credentialPrefix$keyId:title", title)
            // Cleanup of old fields if present
            remove("$credentialPrefix$keyId:username")
            remove("$credentialPrefix$keyId:email")
            remove("$credentialPrefix$keyId:password")
        }
        
        Arrays.fill(username, '\u0000')
        Arrays.fill(email, '\u0000')
        Arrays.fill(password, '\u0000')
    }

    fun getCredential(title: String, cipher: Cipher): Credential? {
        val keyId = encodeKey(title)
        val encData = sharedPreferences.getString("$credentialPrefix$keyId:data", null) ?: return null
        val storedTitle = sharedPreferences.getString("$credentialPrefix$keyId:title", title) ?: title

        return try {
            val decryptedBlob = cipher.doFinal(Base64.decode(encData, Base64.DEFAULT))
            val buffer = ByteBuffer.wrap(decryptedBlob)
            
            fun readField(): String {
                val len = buffer.getInt()
                val bytes = ByteArray(len)
                buffer.get(bytes)
                return String(bytes, StandardCharsets.UTF_8)
            }
            
            Credential(storedTitle, readField(), readField(), readField())
        } catch (e: Exception) {
            null
        }
    }

    fun getIvForCredential(title: String): ByteArray? {
        val keyId = encodeKey(title)
        val ivString = sharedPreferences.getString("$credentialPrefix$keyId:iv", null) ?: return null
        return Base64.decode(ivString, Base64.DEFAULT)
    }

    fun getAllCredentialTitles(): List<String> {
        return sharedPreferences.all.keys
            .filter { it.startsWith(credentialPrefix) && it.endsWith(":title") }
            .mapNotNull { sharedPreferences.getString(it, null) }
            .sorted()
    }

    fun deleteCredential(title: String) {
        val keyId = encodeKey(title)
        sharedPreferences.edit {
            remove("$credentialPrefix$keyId:data")
            remove("$credentialPrefix$keyId:iv")
            remove("$credentialPrefix$keyId:title")
        }
    }

    private fun encodeKey(value: String): String = Base64.encodeToString(value.toByteArray(), Base64.NO_WRAP)
}
