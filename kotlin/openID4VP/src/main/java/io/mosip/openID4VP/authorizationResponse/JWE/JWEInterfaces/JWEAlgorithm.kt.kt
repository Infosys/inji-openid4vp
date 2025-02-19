import javax.crypto.SecretKey

interface JWEAlgorithm {
    fun deriveKey(publicKey: ByteArray): SecretKey

    fun getEphemeralPublicKey(): Map<String, Any>?

    fun getEncryptedKey(): String

    fun getJWEHeader(config: JWEEncryptionConfig, jwk: JWK): Map<String, Any>
}
