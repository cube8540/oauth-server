package cube8540.oauth.authentication.credentials.oauth.error;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class OAuth2ErrorSerializerTest {

    private static final String ERROR_CODE = OAuth2ErrorCodes.INVALID_REQUEST;

    private static final String ERROR_DESCRIPTION = "INVALID REQUEST";

    private OAuth2Error error;
    private JsonGenerator jsonGenerator;
    private SerializerProvider provider;

    private OAuth2ErrorSerializer serializer;

    @BeforeEach
    void setup() {
        this.error = new OAuth2Error(ERROR_CODE, ERROR_DESCRIPTION, null);
        this.jsonGenerator = mock(JsonGenerator.class);
        this.provider = mock(SerializerProvider.class);
        this.serializer = new OAuth2ErrorSerializer();
    }

    @Test
    @DisplayName("JsonGenerator 객체의 writeStartObject 메소드를 한번 호출해야 한다.")
    void shouldCallJsonGeneratorWriteStartObject() throws Exception {
        serializer.serialize(error, jsonGenerator, provider);

        verify(jsonGenerator, times(1)).writeStartObject();
    }

    @Test
    @DisplayName("JsonGenerator에 애러 코드를 적어야 한다.")
    void shouldWriteErrorCodeInJsonGenerator() throws Exception {
        serializer.serialize(error, jsonGenerator, provider);

        verify(jsonGenerator, times(1)).writeStringField(OAuth2Utils.ErrorMessageKey.ERROR, ERROR_CODE);
    }

    @Test
    @DisplayName("JsonGenerator에 에러 설명 적어야 한다.")
    void shouldWriteErrorDescriptionInJsonGenerator() throws Exception {
        serializer.serialize(error, jsonGenerator, provider);

        verify(jsonGenerator, times(1)).writeStringField(OAuth2Utils.ErrorMessageKey.DESCRIPTION, ERROR_DESCRIPTION);
    }

    @Test
    @DisplayName("JsonGenerator 객체의 writeEndObject 메소드를 호출해야 한다.")
    void shouldCallJsonGeneratorWriteEndObject() throws Exception {
        serializer.serialize(error, jsonGenerator, provider);

        verify(jsonGenerator, times(1)).writeEndObject();
    }
}