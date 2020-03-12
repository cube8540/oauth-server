package cube8540.oauth.authentication.credentials.oauth.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import cube8540.oauth.authentication.credentials.oauth.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RefreshTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 엑세스 토큰 직렬화 클래스 테스트")
class OAuth2AccessTokenDetailsSerializerTest {

    private static abstract class Oauth2AccessTokenAssertSetup {

        protected static final String TOKEN_VALUE = "TOKEN-VALUE";
        protected static final String REFRESH_TOKEN_VALUE = "REFRESH-TOKEN";
        protected static final long EXPIRES_IN = 60000L;
        protected static final String TOKEN_TYPE = "TOKEN_TYPE";
        protected static final Set<OAuth2ScopeId> SCOPE = new HashSet<>(Arrays.asList(new OAuth2ScopeId("SCOPE-1"), new OAuth2ScopeId("SCOPE-2"), new OAuth2ScopeId("SCOPE-3")));
        protected static final Map<String, String> ADDITIONAL_INFORMATION = new HashMap<>();

        protected OAuth2AccessTokenDetails accessToken;
        protected JsonGenerator jsonGenerator;
        protected SerializerProvider provider;

        protected OAuth2AccessTokenDetailsSerializer serializer;

        @BeforeEach
        void setup() {
            this.accessToken = mock(OAuth2AccessTokenDetails.class);
            this.jsonGenerator = mock(JsonGenerator.class);
            this.provider = mock(SerializerProvider.class);

            ADDITIONAL_INFORMATION.put("TEST-1", "TEST-1-VALUE");
            ADDITIONAL_INFORMATION.put("TEST-2", "TEST-2-VALUE");
            ADDITIONAL_INFORMATION.put("TEST-3", "TEST-3-VALUE");

            when(accessToken.getTokenValue()).thenReturn(TOKEN_VALUE);
            when(accessToken.getTokenType()).thenReturn(TOKEN_TYPE);
            when(accessToken.getExpiresIn()).thenReturn(EXPIRES_IN);
            when(accessToken.getScopes()).thenReturn(SCOPE);
            when(accessToken.getAdditionalInformation()).thenReturn(null);
            when(accessToken.getRefreshToken()).thenReturn(null);

            this.serializer = new OAuth2AccessTokenDetailsSerializer();
        }

        @Test
        @DisplayName("JsonGenerator 객체의 writeStartObject 메소드를 한번 호출해야 한다.")
        void shouldCallJsonGeneratorWriteStartObject() throws Exception {
            serializer.serialize(accessToken, jsonGenerator, provider);

            verify(jsonGenerator, times(1)).writeStartObject();
        }

        @Test
        @DisplayName("JsonGenerator 에 엑세스 토큰을 적어야 한다.")
        void shouldWriteAccessTokenValueInJsonGenerator() throws Exception {
            serializer.serialize(accessToken, jsonGenerator, provider);

            verify(jsonGenerator, times(1)).writeStringField(OAuth2Utils.AccessTokenSerializeKey.ACCESS_TOKEN, TOKEN_VALUE);
        }

        @Test
        @DisplayName("JsonGenerator 에 엑세스 토큰의 타입을 적어야 한다.")
        void shouldWriteAccessTokenTypeInJsonGenerator() throws Exception {
            serializer.serialize(accessToken, jsonGenerator, provider);

            verify(jsonGenerator, times(1)).writeStringField(OAuth2Utils.AccessTokenSerializeKey.TOKEN_TYPE, TOKEN_TYPE);
        }

        @Test
        @DisplayName("JsonGenerator 에 남은 시간을 적어야 한다.")
        void shouldWriteExpiresInJsonGenerator() throws Exception {
            serializer.serialize(accessToken, jsonGenerator, provider);

            verify(jsonGenerator, times(1)).writeNumberField(OAuth2Utils.AccessTokenSerializeKey.EXPIRES_IN, EXPIRES_IN);
        }

        @Test
        @DisplayName("JsonGenerator 에 스코프를 적어야 한다.")
        void shouldWriteScopeInJsonGenerator() throws Exception {
            serializer.serialize(accessToken, jsonGenerator, provider);

            String excepted = String.join(" ", SCOPE.stream().map(OAuth2ScopeId::getValue).collect(Collectors.toSet()));
            verify(jsonGenerator, times(1))
                    .writeStringField(OAuth2Utils.AccessTokenSerializeKey.SCOPE, excepted);
        }

        @Test
        @DisplayName("JsonGenerator 객체의 writeEndObject 메소드를 호출해야 한다.")
        void shouldCallJsonGeneratorWriteEndObject() throws Exception {
            serializer.serialize(accessToken, jsonGenerator, provider);

            verify(jsonGenerator, times(1)).writeEndObject();
        }
    }

    @Nested
    @DisplayName("리플래시 토큰이 NULL 이 아닐시")
    class WhenRefreshTokenNotNull extends Oauth2AccessTokenAssertSetup {

        @BeforeEach
        void setupRefreshToken() {
            OAuth2RefreshTokenDetails refreshToken = mock(OAuth2RefreshTokenDetails.class);

            when(refreshToken.getTokenValue()).thenReturn(REFRESH_TOKEN_VALUE);
            when(accessToken.getRefreshToken()).thenReturn(refreshToken);
        }

        @Test
        @DisplayName("JsonGenerator 에 리플래시 토큰을 적어야 한다.")
        void shouldWriteRefreshTokenInJsonGenerator() throws Exception {
            serializer.serialize(accessToken, jsonGenerator, provider);

            verify(jsonGenerator, times(1)).writeStringField(OAuth2Utils.AccessTokenSerializeKey.REFRESH_TOKEN, REFRESH_TOKEN_VALUE);
        }
    }

    @Nested
    @DisplayName("추가 정보가 NULL 이 아닐시")
    class WhenAdditionalInformationNotNull extends Oauth2AccessTokenAssertSetup {

        @BeforeEach
        void setupAdditional() {
            when(accessToken.getAdditionalInformation()).thenReturn(ADDITIONAL_INFORMATION);
        }

        @Test
        @DisplayName("JsonGenerator 에 추가 확장 정보를 적어야 한다.")
        void shouldWriteAdditionalInformationInJsonGenerator() throws Exception {
            serializer.serialize(accessToken, jsonGenerator, provider);

            verify(jsonGenerator, times(1)).writeStringField("TEST-1", "TEST-1-VALUE");
            verify(jsonGenerator, times(1)).writeStringField("TEST-2", "TEST-2-VALUE");
            verify(jsonGenerator, times(1)).writeStringField("TEST-3", "TEST-3-VALUE");
        }
    }
}