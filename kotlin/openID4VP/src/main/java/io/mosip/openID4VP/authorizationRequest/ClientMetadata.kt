package io.mosip.openID4VP.authorizationRequest

import Generated
import io.mosip.openID4VP.common.Logger
import isNeitherNullNorEmpty
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

private val className = ClientMetadata::class.simpleName!!

object ClientMetadataSerializer : KSerializer<ClientMetadata> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ClientMetadata") {
		element<String>("name")
		element<String>("logo_url", isOptional = true)
	}

	override fun deserialize(decoder: Decoder): ClientMetadata {
		val builtInDecoder = decoder.beginStructure(descriptor)
		var name: String? = null
		var logoUrl: String? = null

		loop@ while (true) {
			when (builtInDecoder.decodeElementIndex(descriptor)) {
				CompositeDecoder.DECODE_DONE -> break@loop
				0 -> name = builtInDecoder.decodeStringElement(descriptor, 0)
				1 -> logoUrl = builtInDecoder.decodeStringElement(descriptor, 1)
			}
		}

		builtInDecoder.endStructure(descriptor)

		requireNotNull(name) {
			throw Logger.handleException(
				exceptionType = "MissingInput",
				fieldPath = listOf("client_metadata", "name"),
				className = className
			)
		}
		return ClientMetadata(name = name, logoUrl = logoUrl)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: ClientMetadata) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeStringElement(descriptor, 0, value.name)
		value.logoUrl?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = ClientMetadataSerializer::class)
class ClientMetadata(val name: String, @SerialName("logo_url") val logoUrl: String?) :
	Validatable {
	override fun validate() {
		try {
			require(isNeitherNullNorEmpty(name)) {
				throw Logger.handleException(
					exceptionType = "InvalidInput",
					fieldPath = listOf("client_metadata", "name"),
					className = className
				)
			}
			logoUrl?.let {
				require(isNeitherNullNorEmpty(logoUrl)) {
					throw Logger.handleException(
						exceptionType = "InvalidInput",
						fieldPath = listOf("client_metadata", "logo_url"),
						className = className
					)
				}
			}
		} catch (exception: Exception) {
			throw exception
		}
	}
}