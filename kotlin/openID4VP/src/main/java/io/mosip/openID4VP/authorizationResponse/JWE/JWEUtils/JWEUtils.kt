import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import java.util.Base64

@Throws(Exception::class)
fun encodeJWEComponents(
    header: Map<String, Any>,
    encryptedKey: String,
    nonce: ByteArray,
    ciphertext: ByteArray,
    tag: ByteArray
): String {
    val headerJson = Json.encodeToJsonElement(header) as JsonObject
    val encodedHeader = base64URLEscaped(headerJson.toString().toByteArray())

    val encodedEncryptedKey = encryptedKey
    val encodedIV = base64URLEscaped(nonce)
    val encodedCiphertext = base64URLEscaped(ciphertext)
    val encodedAuthTag = base64URLEscaped(tag)

    return listOf(
        encodedHeader,
        encodedEncryptedKey,
        encodedIV,
        encodedCiphertext,
        encodedAuthTag
    ).joinToString(".")
}

@Throws(Exception::class)
fun validateField(value: String, fieldName: String) {
    if (value.isEmpty()) {
        throw Logger.handleException(
            exceptionType = "InvalidJwksInput",
            fieldPath = listOf("jwks", fieldName),
            className = JWK::class.java.simpleName
        )
    }
}

fun base64URLEscaped(data: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(data)
}