package cube8540.oauth.authentication.oauth.converter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import cube8540.oauth.authentication.oauth.AccessTokenSerializeKey;
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2RefreshTokenDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 엑세스 토큰 직렬화 클래스 테스트")
class OAuth2AccessTokenDetailsSerializerTest {

    protected static final String TOKEN_VALUE = "TOKEN-VALUE";
    protected static final String REFRESH_TOKEN_VALUE = "REFRESH-TOKEN";
    protected static final long EXPIRES_IN = 60000L;
    protected static final String TOKEN_TYPE = "TOKEN_TYPE";
    protected static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    protected static final Map<String, String> ADDITIONAL_INFORMATION = new LinkedHashMap<>();

    @Test
    @DisplayName("직렬화")
    void serialize() throws Exception {
        OAuth2AccessTokenDetails accessToken = makeAccessToken();
        JsonGenerator jsonGenerator = mock(JsonGenerator.class);
        SerializerProvider provider = mock(SerializerProvider.class);
        OAuth2AccessTokenDetailsSerializer serializer = new OAuth2AccessTokenDetailsSerializer();

        String excepted = String.join(" ", new HashSet<>(RAW_SCOPES));
        serializer.serialize(accessToken, jsonGenerator, provider);
        InOrder inOrder = inOrder(jsonGenerator);
        inOrder.verify(jsonGenerator, times(1)).writeStartObject();
        inOrder.verify(jsonGenerator, times(1)).writeStringField(AccessTokenSerializeKey.ACCESS_TOKEN, TOKEN_VALUE);
        inOrder.verify(jsonGenerator, times(1)).writeStringField(AccessTokenSerializeKey.TOKEN_TYPE, TOKEN_TYPE);
        inOrder.verify(jsonGenerator, times(1)).writeNumberField(AccessTokenSerializeKey.EXPIRES_IN, EXPIRES_IN);
        inOrder.verify(jsonGenerator, times(1)).writeStringField(AccessTokenSerializeKey.SCOPE, excepted);
        inOrder.verify(jsonGenerator, times(1)).writeStringField(AccessTokenSerializeKey.REFRESH_TOKEN, REFRESH_TOKEN_VALUE);
        inOrder.verify(jsonGenerator, times(1)).writeStringField("TEST-1", "TEST-1-VALUE");
        inOrder.verify(jsonGenerator, times(1)).writeStringField("TEST-2", "TEST-2-VALUE");
        inOrder.verify(jsonGenerator, times(1)).writeStringField("TEST-3", "TEST-3-VALUE");
        inOrder.verify(jsonGenerator, times(1)).writeEndObject();
    }

    private OAuth2AccessTokenDetails makeAccessToken() {
        OAuth2AccessTokenDetails accessToken = mock(OAuth2AccessTokenDetails.class);
        OAuth2RefreshTokenDetails refreshToken = mock(OAuth2RefreshTokenDetails.class);

        ADDITIONAL_INFORMATION.put("TEST-1", "TEST-1-VALUE");
        ADDITIONAL_INFORMATION.put("TEST-2", "TEST-2-VALUE");
        ADDITIONAL_INFORMATION.put("TEST-3", "TEST-3-VALUE");
        when(accessToken.getTokenValue()).thenReturn(TOKEN_VALUE);
        when(accessToken.getTokenType()).thenReturn(TOKEN_TYPE);
        when(accessToken.getExpiresIn()).thenReturn(EXPIRES_IN);
        when(accessToken.getScopes()).thenReturn(RAW_SCOPES);
        when(accessToken.getAdditionalInformation()).thenReturn(null);
        when(accessToken.getRefreshToken()).thenReturn(null);
        when(accessToken.getAdditionalInformation()).thenReturn(ADDITIONAL_INFORMATION);

        when(refreshToken.getTokenValue()).thenReturn(REFRESH_TOKEN_VALUE);
        when(accessToken.getRefreshToken()).thenReturn(refreshToken);

        return accessToken;
    }
}