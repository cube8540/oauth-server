package cube8540.oauth.authentication.oauth.error

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import cube8540.oauth.authentication.oauth.ErrorMessageKey
import io.mockk.mockk
import io.mockk.verifyOrder
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

class OAuth2ErrorSerializerTest {

    private val serializer = OAuth2ErrorSerializer()

    @Test
    fun `oauth2 error serialize`() {
        val error = OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "invalid request", null)
        val jsonGenerator: JsonGenerator = mockk(relaxed = true)
        val provider: SerializerProvider = mockk()

        serializer.serialize(error, jsonGenerator, provider)
        verifyOrder {
            jsonGenerator.writeStartObject()
            jsonGenerator.writeStringField(ErrorMessageKey.ERROR, OAuth2ErrorCodes.INVALID_REQUEST)
            jsonGenerator.writeStringField(ErrorMessageKey.DESCRIPTION, "invalid request")
            jsonGenerator.writeEndObject()
        }
    }

}