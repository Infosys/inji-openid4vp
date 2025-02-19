package io.mosip.openID4VP.jwe.service

import io.mosip.openID4VP.jwe.exception.JWEException
import io.mosip.openID4VP.jwe.models.JWEEncryptionConfig
import io.mosip.openID4VP.jwe.models.JWK
import java.util.Base64
import javax.crypto.SecretKey

class JWEEncryptionService(
    private val config: JWEEncryptionConfig,
    private val jwk: JWK
) {
    companion object {
        val className = JWEEncryptionService::class.java.simpleName
    }

    @Throws(Exception::class)
    fun encryptPayload(payload: String): String {
        val algorithm = getAlgorithm()
        val encryption = getEncryption()

        val publicKeyData = Base64.getDecoder().decode(makeBase64Standard(jwk.x))
            ?: throw JWEException.PublicKeyConversionFailed()

        val contentEncryptionKey = algorithm.deriveKey(publicKeyData)

        val payloadData = payload.toByteArray(Charsets.UTF_8)
            ?: throw JWEException.PayloadConversionFailed()

        val (ciphertext, nonce, tag) = encryption.encrypt(payloadData, contentEncryptionKey)

        val header = algorithm.getJWEHeader(config, jwk).toMutableMap()

        algorithm.getEphemeralPublicKey()?.let {
            header["epk"] = it
        }

        return encodeJWEComponents(
            header = header,
            encryptedKey = algorithm.getEncryptedKey(),
            nonce = nonce,
            ciphertext = ciphertext,
            tag = tag
        )
    }

    @Throws(Exception::class)
    private fun getAlgorithm(): JWEAlgorithm {
        return when (config.alg) {
            "ECDH-ES" -> ECDHESAlgorithm()
            else -> throw JWEException.UnsupportedKeyExchangeAlgorithm()
        }
    }

    @Throws(Exception::class)
    private fun getEncryption(): JWEEncryption {
        return when (config.enc) {
            "A256GCM" -> AESGCMEncryption()
            else -> throw JWEException.UnsupportedEncryptionAlgorithm()
        }
    }

    private fun makeBase64Standard(base64: String): String {
        return base64.replace('-', '+').replace('_', '/')
    }
}