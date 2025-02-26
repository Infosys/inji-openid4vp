import io.mosip.openID4VP.jwe.models.JWEEncryptionConfig
import io.mosip.openID4VP.jwe.models.JWK
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.agreement.ECDHCStagedAgreement
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.util.encoders.Base64
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.Mac

class ECDHESAlgorithm : JWEAlgorithm {

    private var ephemeralKeyPair: AsymmetricCipherKeyPair? = null

    init {
        java.security.Security.addProvider(BouncyCastleProvider())
    }

    @Throws(Exception::class)
    override fun deriveKey(publicKey: ByteArray): SecretKey {
//        val keyPairGenerator = KeyPairGenerator.getInstance("X25519", "BC")
//        keyPairGenerator.initialize(ECGenParameterSpec("X25519"), SecureRandom())
//        val privateKey = keyPairGenerator.generateKeyPair().private
//        ephemeralKeyPair = keyPairGenerator.generateKeyPair()
//        val publicKeySpec = ECPublicKeySpec(
//            java.security.KeyFactory.getInstance("X25519")
//                .generatePublic(ECPublicKeySpec(publicKey, ECParameterSpec("X25519"))),
//            ECParameterSpec("X25519")
//        )

//        ephemeralKeyPair = X25519KeyPairGenerator().generateKeyPair()

        val eckeyPair = ECKeyPairGenerator().generateKeyPair()
        ephemeralKeyPair = eckeyPair
        println(eckeyPair.getPrivate())
        val publicKeySpecData = X25519PublicKeyParameters(publicKey)
        val privateKeySpecData = Ed25519PrivateKeyParameters(eckeyPair.private.toString().toByteArray())

//        println(publicKeySpecData.encoded)
//        val keyFactory = KeyFactory.getInstance("X25519", "BC")
//        keyFactory.generatePublic(publicKeySpecData)

        println("eckeyPair.toECPrivateKey().encoded")

        val keyAgreement =  ECDHCStagedAgreement()
        keyAgreement.init(privateKeySpecData)
        val sharedSecret = keyAgreement.calculateAgreement(publicKeySpecData)
        keyAgreement.calculateStage(publicKeySpecData)

//        val keyAgreement = KeyAgreement.getInstance("X25519")
//        keyAgreement.init(privateKey)
//        keyAgreement.doPhase(, true)
//        val sharedSecret = keyAgreement.generateSecret()
        println(sharedSecret)
        return deriveSymmetricKey(sharedSecret.toByteArray())
    }

    private fun deriveSymmetricKey(sharedSecret: ByteArray): SecretKey {
        val salt = "ECDH-ES+A256GCM".toByteArray()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        println(sharedSecret)

        val derivedKey = mac.doFinal(sharedSecret)
        return SecretKeySpec(derivedKey.copyOf(32), "AES")
    }

    override fun getEphemeralPublicKey(): Map<String, Any>? {
        val publicKey = ephemeralKeyPair?.public ?: return null
        return mapOf(
            "kty" to "OKP",
            "crv" to "X25519",
            "x" to Base64.encode(publicKey.toString().toByteArray()).toString(Charsets.UTF_8)
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