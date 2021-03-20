package cube8540.oauth.authentication.oauth.converter

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import cube8540.oauth.authentication.oauth.AccessTokenSerializeKey
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import io.mockk.every
import io.mockk.mockk
import io.mockk.verifyOrder
import org.junit.jupiter.api.Test

class OAuth2accessTokenDetailsSerializerTest {

    private val serializer = OAuth2AccessTokenDetailsSerializer()

    @Test
    fun `access token serialize`() {
        val accessToke: OAuth2AccessTokenDetails = mockk {
            every { tokenValue } returns "tokenValue"
            every { tokenType } returns "tokenType"
            every { expiresIn } returns 100L
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
            every { additionalInformation } returns
                    mapOf("test-1" to "test-1-value", "test-2" to "test-2-value", "test-3" to "test-3-value")
            every { refreshToken } returns mockk {
                every { tokenValue } returns "refreshTokenValue"
            }
        }
        val jsonGenerator: JsonGenerator = mockk(relaxed = true)
        val provider: SerializerProvider = mockk()

        serializer.serialize(accessToke, jsonGenerator, provider)
        verifyOrder {
            jsonGenerator.writeStartObject()
            jsonGenerator.writeStringField(AccessTokenSerializeKey.ACCESS_TOKEN, "tokenValue")
            jsonGenerator.writeStringField(AccessTokenSerializeKey.TOKEN_TYPE, "tokenType")
            jsonGenerator.writeNumberField(AccessTokenSerializeKey.EXPIRES_IN, 100L)
            jsonGenerator.writeStringField(AccessTokenSerializeKey.SCOPE, "scope-1 scope-2 scope-3")
            jsonGenerator.writeStringField(AccessTokenSerializeKey.REFRESH_TOKEN, "refreshTokenValue")
            jsonGenerator.writeStringField("test-1", "test-1-value")
            jsonGenerator.writeStringField("test-2", "test-2-value")
            jsonGenerator.writeStringField("test-3", "test-3-value")
            jsonGenerator.writeEndObject()
        }
    }

}