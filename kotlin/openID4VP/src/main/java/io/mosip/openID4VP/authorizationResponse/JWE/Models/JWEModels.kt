package io.mosip.openID4VP.jwe.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class JWEEncryptionConfig(
    val alg: String,
    val enc: String
)

@Serializable
data class JWKS(
    val keys: List<JWK>
) {
    companion object {
        val className = JWKS::class.java.simpleName
    }

    @Throws(Exception::class)
    fun validate() {
        keys.forEachIndexed { index, key ->
            try {
                key.validate()
            } catch (e: Exception) {
                throw Logger.handleException(
                    exceptionType = "InvalidJwksInput",
                    fieldPath = listOf("jwks", "keys", index.toString()),
                    className = className
                )
            }
        }
    }
}

@Serializable
data class JWK(
    val kty: String,
    val use: String,
    val crv: String,
    val x: String,
    val alg: String,
    val kid: String,
    val y: String? = null
) {
    companion object {
        val className = JWK::class.java.simpleName
    }

    @Throws(Exception::class)
    fun validate() {
        val requiredFields = listOf(
            kty to "kty",
            use to "use",
            crv to "crv",
            x to "x",
            alg to "alg",
            kid to "kid"
        )

        requiredFields.forEach { (value, fieldName) ->
            validateField(value, fieldName)
        }

        y?.let {
            validateField(it, "y")
        }
    }

    @Throws(Exception::class)
    private fun validateField(value: String, fieldName: String) {
        if (value.isEmpty()) {
            throw Exception("Invalid field: $fieldName is empty")
        }
    }
}