package cube8540.oauth.authentication.oauth.converter

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import cube8540.oauth.authentication.oauth.AccessTokenSerializeKey
import cube8540.oauth.authentication.oauth.extractGrantType
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import org.springframework.security.oauth2.core.AuthorizationGrantType
import java.net.URI
import javax.persistence.AttributeConverter

class RedirectUriConverter: AttributeConverter<URI, String> {
    override fun convertToDatabaseColumn(attribute: URI?): String? = attribute?.toString()

    override fun convertToEntityAttribute(dbData: String?): URI? = dbData?.let { URI.create(it) }
}

class AuthorizationGrantTypeConverter: AttributeConverter<AuthorizationGrantType, String> {
    override fun convertToDatabaseColumn(attribute: AuthorizationGrantType): String = attribute.value

    override fun convertToEntityAttribute(dbData: String): AuthorizationGrantType = extractGrantType(dbData)
}

class CodeChallengeConverter: AttributeConverter<CodeChallenge, String> {
    override fun convertToDatabaseColumn(attribute: CodeChallenge?): String? = attribute?.value

    override fun convertToEntityAttribute(dbData: String?): CodeChallenge? = dbData?.let { CodeChallenge.parse(it) }
}

class CodeChallengeMethodConverter: AttributeConverter<CodeChallengeMethod, String> {
    override fun convertToDatabaseColumn(attribute: CodeChallengeMethod?): String? = attribute?.toString()

    override fun convertToEntityAttribute(dbData: String?): CodeChallengeMethod? = dbData?.let { CodeChallengeMethod.parse(it) }
}

class OAuth2AccessTokenDetailsSerializer: StdSerializer<OAuth2AccessTokenDetails>(OAuth2AccessTokenDetails::class.java) {
    override fun serialize(value: OAuth2AccessTokenDetails, gen: JsonGenerator, provider: SerializerProvider) {
        gen.writeStartObject()

        gen.writeStringField(AccessTokenSerializeKey.ACCESS_TOKEN, value.tokenValue)
        gen.writeStringField(AccessTokenSerializeKey.TOKEN_TYPE, value.tokenType)
        gen.writeNumberField(AccessTokenSerializeKey.EXPIRES_IN, value.expiresIn)

        writeScopeField(value, gen)
        writeRefreshTokenField(value, gen)
        writeAdditionalInformationField(value, gen)

        gen.writeEndObject()
    }

    private fun writeAdditionalInformationField(value: OAuth2AccessTokenDetails, generator: JsonGenerator) =
        value.additionalInformation?.entries?.forEach { generator.writeStringField(it.key, it.value)}

    private fun writeRefreshTokenField(value: OAuth2AccessTokenDetails, generator: JsonGenerator) =
        generator.writeStringField(AccessTokenSerializeKey.REFRESH_TOKEN, value.refreshToken?.tokenValue)

    private fun writeScopeField(value: OAuth2AccessTokenDetails, generator: JsonGenerator) {
        val scopes = value.scopes?.joinToString(" ")
        if (scopes != null) {
            generator.writeStringField(AccessTokenSerializeKey.SCOPE, scopes)
        }
    }

}