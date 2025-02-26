import io.mosip.openID4VP.jwe.models.JWEEncryptionConfig
import io.mosip.openID4VP.jwe.models.JWK
import javax.crypto.SecretKey

interface JWEAlgorithm {
    fun deriveKey(publicKey: ByteArray): SecretKey

    fun getEphemeralPublicKey(): Map<String, Any>?

    fun getEncryptedKey(): String

    fun getJWEHeader(config: JWEEncryptionConfig, jwk: JWK): Map<String, Any>
}
