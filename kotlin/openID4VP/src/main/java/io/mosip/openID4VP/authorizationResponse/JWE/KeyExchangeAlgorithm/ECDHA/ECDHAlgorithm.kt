import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.jce.spec.ECGenParameterSpec
import org.bouncycastle.util.encoders.Base64
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.PBEKeySpec
import javax.crypto.SecretKeyFactory

class ECDHESAlgorithm : JWEAlgorithm {

    private var ephemeralKeyPair: KeyPair? = null

    init {
        java.security.Security.addProvider(BouncyCastleProvider())
    }

    @Throws(Exception::class)
    override fun deriveKey(publicKey: ByteArray): SecretKey {
        val keyPairGenerator = KeyPairGenerator.getInstance("X25519")
        keyPairGenerator.initialize(ECGenParameterSpec("X25519"), SecureRandom())
        val privateKey = keyPairGenerator.generateKeyPair().private
        val publicKeySpec = ECPublicKeySpec(
            java.security.KeyFactory.getInstance("X25519")
                .generatePublic(ECPublicKeySpec(publicKey, ECParameterSpec("X25519"))),
            ECParameterSpec("X25519")
        )

        ephemeralKeyPair = keyPairGenerator.generateKeyPair()

        val keyAgreement = KeyAgreement.getInstance("X25519")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKeySpec, true)

        val sharedSecret = keyAgreement.generateSecret()
        return deriveSymmetricKey(sharedSecret)
    }

    private fun deriveSymmetricKey(sharedSecret: ByteArray): SecretKey {
        val salt = "ECDH-ES+A256GCM".toByteArray()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))

        val derivedKey = mac.doFinal(sharedSecret)
        return SecretKeySpec(derivedKey.copyOf(32), "AES")
    }

    override fun getEphemeralPublicKey(): Map<String, Any>? {
        val publicKey = ephemeralKeyPair?.public ?: return null
        return mapOf(
            "kty" to "OKP",
            "crv" to "X25519",
            "x" to Base64.encode(publicKey.encoded).toString(Charsets.UTF_8)
        )
    }

    override fun getEncryptedKey(): String {
        return ""
    }

    override fun getJWEHeader(config: JWEEncryptionConfig, jwk: JWK): Map<String, Any> {
        return mapOf(
            "alg" to config.alg,
            "enc" to config.enc,
            "kid" to jwk.kid
        )
    }
}