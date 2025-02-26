import javax.crypto.SecretKey

interface JWEEncryption {
    fun encrypt(data: ByteArray, key: SecretKey): Triple<ByteArray, ByteArray, ByteArray>
}