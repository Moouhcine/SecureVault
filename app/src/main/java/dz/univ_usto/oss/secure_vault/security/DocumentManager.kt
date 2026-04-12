package dz.univ_usto.oss.secure_vault.security

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Base64
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.UUID

class DocumentManager(private val context: Context) {
    data class DocumentEntry(
        val id: String,
        val displayName: String,
        val mimeType: String,
        val fileName: String,
        val originalUri: String?,
        val sourceSanitized: Boolean
    )

    data class ImportResult(
        val success: Boolean,
        val sourceSanitized: Boolean,
        val message: String
    )

    private val docPrefix = "doc:"
    private val docsDir = File(context.filesDir, "documents").apply { mkdirs() }
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = try {
        EncryptedSharedPreferences.create(
            context,
            "secure_vault_docs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    } catch (e: Exception) {
        context.deleteSharedPreferences("secure_vault_docs")
        EncryptedSharedPreferences.create(
            context,
            "secure_vault_docs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private var lastError: String? = null

    fun importDocument(uri: Uri, displayName: String, mimeType: String): ImportResult {
        lastError = null
        return try {
            val id = UUID.randomUUID().toString()
            val fileName = "doc_${id}.bin"
            val encryptedTarget = File(docsDir, fileName)
            val encryptedFile = EncryptedFile.Builder(
                context,
                encryptedTarget,
                masterKey,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build()

            val inputStream = context.contentResolver.openInputStream(uri) ?: run {
                lastError = "Cannot open input stream"
                return ImportResult(
                    success = false,
                    sourceSanitized = false,
                    message = lastError.orEmpty()
                )
            }
            inputStream.use { input ->
                encryptedFile.openFileOutput().use { output ->
                    input.copyTo(output)
                }
            }

            val sourceSanitized = sanitizeSourceDocument(uri)
            val key = encodeKey(id)
            prefs.edit {
                putString("$docPrefix$key:name", displayName)
                putString("$docPrefix$key:mime", mimeType)
                putString("$docPrefix$key:file", fileName)
                putString("$docPrefix$key:origin", uri.toString())
                putBoolean("$docPrefix$key:sanitized", sourceSanitized)
            }

            val message = if (sourceSanitized) {
                "Document moved into the vault"
            } else {
                "Document imported, but the original file could not be wiped"
            }

            ImportResult(
                success = true,
                sourceSanitized = sourceSanitized,
                message = message
            )
        } catch (e: Exception) {
            lastError = e.javaClass.simpleName
            ImportResult(
                success = false,
                sourceSanitized = false,
                message = lastError.orEmpty()
            )
        }
    }

    fun getLastError(): String? = lastError

    fun exportDocument(id: String, destination: Uri): Boolean {
        val entry = getDocument(id) ?: return false
        val exported = writeDocumentToUri(entry, destination)
        if (exported) {
            deleteDocument(id)
        }
        return exported
    }

    fun exportDocumentToOriginal(id: String): Boolean {
        val entry = getDocument(id) ?: return false
        val origin = entry.originalUri ?: return false
        val destination = Uri.parse(origin)
        return exportDocument(id, destination)
    }

    fun deleteDocument(id: String) {
        val entry = getDocument(id) ?: return
        File(docsDir, entry.fileName).delete()
        val key = encodeKey(id)
        prefs.edit {
            remove("$docPrefix$key:name")
            remove("$docPrefix$key:mime")
            remove("$docPrefix$key:file")
            remove("$docPrefix$key:origin")
            remove("$docPrefix$key:sanitized")
        }
    }

    fun listDocuments(): List<DocumentEntry> {
        val ids = prefs.all.keys
            .filter { it.startsWith(docPrefix) && it.endsWith(":file") }
            .mapNotNull { key -> key.removePrefix(docPrefix).removeSuffix(":file") }
            .mapNotNull { decodeKey(it) }

        return ids.mapNotNull { getDocument(it) }.sortedBy { it.displayName.lowercase() }
    }

    fun getDocument(id: String): DocumentEntry? {
        val key = encodeKey(id)
        val name = prefs.getString("$docPrefix$key:name", null) ?: return null
        val mime = prefs.getString("$docPrefix$key:mime", "application/octet-stream") ?: "application/octet-stream"
        val file = prefs.getString("$docPrefix$key:file", null) ?: return null
        val origin = prefs.getString("$docPrefix$key:origin", null)
        val sourceSanitized = prefs.getBoolean("$docPrefix$key:sanitized", false)
        return DocumentEntry(id, name, mime, file, origin, sourceSanitized)
    }

    private fun encodeKey(value: String): String {
        return Base64.encodeToString(value.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
    }

    private fun decodeKey(value: String): String? {
        return try {
            String(Base64.decode(value, Base64.NO_WRAP), StandardCharsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    private fun writeDocumentToUri(entry: DocumentEntry, destination: Uri): Boolean {
        val encryptedFile = EncryptedFile.Builder(
            context,
            File(docsDir, entry.fileName),
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()

        return context.contentResolver.openOutputStream(destination, "wt")?.use { output ->
            encryptedFile.openFileInput().use { input ->
                input.copyTo(output)
            }
            true
        } ?: false
    }

    private fun sanitizeSourceDocument(uri: Uri): Boolean {
        if (!DocumentsContract.isDocumentUri(context, uri)) return false

        return try {
            context.contentResolver.openOutputStream(uri, "wt")?.use {
                // Truncate the source file so sensitive bytes remain only in the vault.
            } != null
        } catch (_: Exception) {
            false
        }
    }
}

