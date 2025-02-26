package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.ClientMetadata
import io.mosip.openID4VP.authorizationRequest.ResponseMode
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPToken
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.VPTokenForSigning
import io.mosip.openID4VP.common.Logger
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.dto.VPResponseMetadata
import io.mosip.openID4VP.jwe.models.JWEEncryptionConfig
import io.mosip.openID4VP.jwe.models.JWK
import io.mosip.openID4VP.jwe.service.JWEEncryptionService
import io.mosip.openID4VP.networkManager.HTTP_METHOD
import io.mosip.openID4VP.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

import java.net.URL

private val logTag = Logger.getLogTag(AuthorizationResponse::class.simpleName!!)
private val className = AuthorizationResponse::class.simpleName!!

@Serializable
data class RequestBody(
    val vpToken: VPToken,
    val presentationSubmission: PresentationSubmission
)

class AuthorizationResponse {
    companion object {
        private lateinit var vpTokenForSigning: VPTokenForSigning
        private lateinit var verifiableCredentials: Map<String, List<String>>

        fun constructVPTokenForSigning(verifiableCredentials: Map<String, List<String>>): String {
            try {
                this.verifiableCredentials = verifiableCredentials
                val verifiableCredential = mutableListOf<String>()
                verifiableCredentials.forEach { (_, vcs) ->
                    vcs.forEach { vcJson ->
                        verifiableCredential.add(vcJson)
                    }
                }
                this.vpTokenForSigning = VPTokenForSigning(
                    verifiableCredential = verifiableCredential,
                    id = UUIDGenerator.generateUUID(),
                    holder = ""
                )
                return Json.encodeToString(vpTokenForSigning)
            } catch (exception: SerializationException) {
                throw Logger.handleException(
                    exceptionType = "JsonEncodingFailed",
                    message = exception.message,
                    fieldPath = listOf("vp_token_for_signing"),
                    className = className
                )
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        fun shareVP(
            vpResponseMetadata: VPResponseMetadata,
            authorizationRequest: AuthorizationRequest,
        ): String {
            try {
                vpResponseMetadata.validate()
                var pathIndex = 0
                val proof = Proof.constructProof(
                    vpResponseMetadata, challenge = authorizationRequest.nonce
                )
                val descriptorMap = mutableListOf<DescriptorMap>()
                verifiableCredentials.forEach { (inputDescriptorId, vcs) ->
                    vcs.forEach { _ ->
                        descriptorMap.add(
                            DescriptorMap(
                                inputDescriptorId,
                                "ldp_vp",
                                "$.verifiableCredential[${pathIndex++}]"
                            )
                        )
                    }
                }
                val presentationSubmission = PresentationSubmission(
                    UUIDGenerator.generateUUID(), authorizationRequest.clientId, descriptorMap
                )
                val vpToken = VPToken.constructVpToken(this.vpTokenForSigning, proof)
                if (authorizationRequest.responseMode == ResponseMode.DirectPostJwt.codable) {
                    return constructJWEAndSendHttpRequest(
                        vpToken = vpToken,
                        authorizationRequest = authorizationRequest,
                        presentationSubmission = presentationSubmission
                    )
                }
                return constructHttpRequestBody(
                    vpToken = vpToken,
                    presentationSubmission = presentationSubmission,
                    responseUri = authorizationRequest.responseUri ?: "",
                    state = authorizationRequest.state
                )
            } catch (exception: Exception) {
                Logger.error(logTag, exception)
                throw exception
            }
        }

        private fun constructHttpRequestBody(
            vpToken: VPToken,
            presentationSubmission: PresentationSubmission,
            responseUri: String, state: String
        ): String {
            val encodedVPToken: String
            val encodedPresentationSubmission: String
            try {
                encodedVPToken = Json.encodeToString(vpToken)
            } catch (exception: Exception) {
                throw Logger.handleException(
                    exceptionType = "JsonEncodingFailed",
                    message = exception.message,
                    fieldPath = listOf("vp_token"),
                    className = className
                )
            }
            try {
                encodedPresentationSubmission = Json.encodeToString(presentationSubmission)
            } catch (exception: Exception) {
                throw Logger.handleException(
                    exceptionType = "JsonEncodingFailed",
                    message = exception.message,
                    fieldPath = listOf("presentation_submission"),
                    className = className
                )
            }

            try {
                val bodyParams = mapOf(
                    "vp_token" to encodedVPToken,
                    "presentation_submission" to encodedPresentationSubmission,
                    "state" to state
                )

                return sendHTTPRequest(
                    url = responseUri,
                    method = HTTP_METHOD.POST,
                    bodyParams = bodyParams,
                    headers = mapOf("Content-Type" to "application/x-www-form-urlencoded")
                )
            } catch (exception: Exception) {
                throw exception
            }
        }

        private fun constructJWEAndSendHttpRequest(
            vpToken: VPToken,
            authorizationRequest: AuthorizationRequest,
            presentationSubmission: PresentationSubmission,
        ): String {

            val clientMetadata = authorizationRequest.clientMetadata as? ClientMetadata
            val jwkFromMetadata = clientMetadata?.jwks?.keys?.firstOrNull()

            if (jwkFromMetadata == null) {
                throw Logger.handleException(
                    exceptionType = "JWEEncryptionFailed",
                    className = AuthorizationResponse::class.java.name
                )
            }

            val alg = clientMetadata.authorizationEncryptedResponseAlg
            val enc = clientMetadata.authorizationEncryptedResponseEnc

            if (alg == null || enc == null) {
                throw Logger.handleException(
                    exceptionType = "EncryptionConfigExtractionFailed",
                    className = AuthorizationResponse::class.java.name
                )
            }

            val responseUri = authorizationRequest.responseUri

            val url = responseUri?.let { URL(it) }
            if (url == null) {
                throw Logger.handleException(
                    exceptionType = "urlCreationFailed",
                    className = AuthorizationResponse::class.java.name
                )
            }
            val jwk = JWK(
                kty = jwkFromMetadata.kty,
                use = jwkFromMetadata.use,
                crv = jwkFromMetadata.crv,
                x = jwkFromMetadata.x,
                alg = jwkFromMetadata.alg,
                kid = jwkFromMetadata.kid
            )
            val config = JWEEncryptionConfig(alg = alg, enc = enc)
            val service = JWEEncryptionService(config = config, jwk = jwk)


            val encodedVPToken: String
            val encodedPresentationSubmission: String
            try {
                encodedVPToken = Json.encodeToString(vpToken)
            } catch (exception: Exception) {
                throw Logger.handleException(
                    exceptionType = "JsonEncodingFailed",
                    message = exception.message,
                    fieldPath = listOf("vp_token"),
                    className = className
                )
            }
            try {
                encodedPresentationSubmission = Json.encodeToString(presentationSubmission)
            } catch (exception: Exception) {
                throw Logger.handleException(
                    exceptionType = "JsonEncodingFailed",
                    message = exception.message,
                    fieldPath = listOf("presentation_submission"),
                    className = className
                )
            }

            val requestBody = """{
                                  "vp_token" to ${encodedVPToken},
                                  "presentation_submission" to ${encodedPresentationSubmission},
                              }""".trimIndent()
            val encryptedPayload = try {
                service.encryptPayload(requestBody)
            } catch (e: Exception) {
                println(e.localizedMessage)
                throw Logger.handleException(
                    exceptionType = "JWEEncryptionFailed",
                    message = e.localizedMessage,
                    className =  AuthorizationResponse::class.java.name
                )
            }
            val bodyParams = mapOf(
                "response" to encryptedPayload,
            )

            return try {
                sendHTTPRequest(
                    url = url.toString(),
                    method = HTTP_METHOD.POST,
                    bodyParams = bodyParams,
                    headers = mapOf("Content-Type" to "application/x-www-form-urlencoded")
                )
            } catch (e: Exception) {
                throw e
            }
        }

    }
}