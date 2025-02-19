package io.mosip.openID4VP.jwe.exception

sealed class JWEExceptions {

    class PublicKeyConversionFailed :
        Exception("Public key Data conversion from base64 failed.")

    class PayloadConversionFailed :
        Exception("Payload data conversion failed.")

    class UnsupportedKeyExchangeAlgorithm :
        Exception("Required Key exchange algorithm is not supported.")

    class UnsupportedEncryptionAlgorithm :
        Exception("Required Encryption algorithm is not supported.")

    class InvalidJwksInput(fieldPath: String) :
        Exception("Invalid Input: $fieldPath param is empty.")
}