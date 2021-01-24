package cube8540.oauth.authentication.oauth.token.application;

import cube8540.oauth.authentication.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 엑세스 토큰 부여 테스트")
class CompositeOAuth2AccessTokenGranterTest {

    private CompositeOAuth2AccessTokenGranter accessTokenGranter;

    @BeforeEach
    void setup() {
        this.accessTokenGranter = new CompositeOAuth2AccessTokenGranter();
    }

    @Test
    @DisplayName("지원 되지 않는 인증 타입 일때")
    void whenNotSupportedGrantType() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();

        when(request.getGrantType()).thenReturn(null);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> accessTokenGranter.grant(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, error.getErrorCode());
    }

    @Test
    @DisplayName("액세스 토큰 생성")
    void generateAccessToken() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AccessTokenDetails token = mock(OAuth2AccessTokenDetails.class);
        OAuth2AccessTokenGranter granter = mock(OAuth2AccessTokenGranter.class);

        when(granter.grant(clientDetails, request)).thenReturn(token);
        when(request.getGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
        accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.AUTHORIZATION_CODE, granter);
        accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.CLIENT_CREDENTIALS, mock(OAuth2AccessTokenGranter.class));
        accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.REFRESH_TOKEN, mock(OAuth2AccessTokenGranter.class));
        accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.PASSWORD, mock(OAuth2AccessTokenGranter.class));

        OAuth2AccessTokenDetails accessToken = accessTokenGranter.grant(clientDetails, request);
        assertEquals(token, accessToken);
    }
}