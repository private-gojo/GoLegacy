package dev.go.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class ProfileStore(context: Context) {
    private val file = AtomicFile(File(context.filesDir, "profiles.enc"))
    private val alias = "dev.go.core.profile-store.v1"
    private val magic = "GOP1".toByteArray(Charsets.US_ASCII)

    fun read(): String {
        if (!file.baseFile.exists()) return "[]"
        val blob = file.openRead().use { it.readBytes() }
        require(blob.size >= magic.size + 12 + 16) { "Encrypted profile store is truncated" }
        require(blob.copyOfRange(0, magic.size).contentEquals(magic)) { "Unsupported profile store format" }
        val nonce = blob.copyOfRange(magic.size, magic.size + 12)
        val ciphertext = blob.copyOfRange(magic.size + 12, blob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, nonce))
        cipher.updateAAD(magic)
        return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
    }

    fun write(plainText: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(magic)
        val nonce = cipher.iv
        val ciphertext = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        val blob = magic + nonce + ciphertext
        var stream: java.io.FileOutputStream? = null
        try {
            stream = file.startWrite()
            stream.write(blob)
            file.finishWrite(stream)
        } catch (e: Exception) {
            if (stream != null) file.failWrite(stream)
            throw e
        }
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = store.getKey(alias, null)
        if (existing is SecretKey) return existing
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }
}
