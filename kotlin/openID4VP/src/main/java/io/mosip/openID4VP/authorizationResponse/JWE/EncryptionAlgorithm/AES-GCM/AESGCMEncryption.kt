import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom
import io.mosip.openID4VP.jwe.exception.JWEExceptions

class AESGCMEncryption : JWEEncryption {
    private val ALGORITHM = "AES"
    private val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
    private val GCM_TAG_LENGTH = 128 // in bits
    private val NONCE_LENGTH = 12 // in bytes

    override fun encrypt(data: ByteArray, key: SecretKey): Triple<ByteArray, ByteArray, ByteArray> {
        val nonce = ByteArray(NONCE_LENGTH)
        SecureRandom().nextBytes(nonce)

        return try {
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            val gcmParameterSpec = GCMParameterSpec(GCM_TAG_LENGTH, nonce)
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec)
            val ciphertext = cipher.doFinal(data)
            Triple(ciphertext, nonce, cipher.iv.takeLast(16).toByteArray())
        } catch (e: Exception) {
            throw JWEExceptions.UnsupportedEncryptionAlgorithm()
        }
    }
}