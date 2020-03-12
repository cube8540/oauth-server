package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.OAuth2AccessTokenDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 엑세스 토큰 부여 테스트")
class CompositeOAuth2AccessTokenGranterTest {

    private CompositeOAuth2AccessTokenGranter accessTokenGranter;

    @BeforeEach
    void setup() {
        this.accessTokenGranter = new CompositeOAuth2AccessTokenGranter();
    }

    @Nested
    @DisplayName("엑세스 토큰 생성")
    class CreateAccessToken {

        @Nested
        @DisplayName("지원되지 않는 인증 타입일시")
        class WhenNotSupportedGrantType {

            private OAuth2ClientDetails clientDetails;
            private OAuth2TokenRequest tokenRequest;

            @BeforeEach
            void setup() {
                this.clientDetails = mock(OAuth2ClientDetails.class);
                this.tokenRequest = mock(OAuth2TokenRequest.class);
            }

            @Test
            @DisplayName("InvalidGrantException이 발생해야 한다.")
            void shouldThrowsInvalidGrantException() {
                assertThrows(InvalidGrantException.class, () -> accessTokenGranter.grant(clientDetails, tokenRequest));
            }

            @Test
            @DisplayName("에러 코드는 UNSUPPORTED_GRANT_TYPE 이어야 한다.")
            void shouldErrorCodeIsUnsupportedGrantType() {
                OAuth2Error error = assertThrows(InvalidGrantException.class, () -> accessTokenGranter.grant(clientDetails, tokenRequest))
                        .getError();
                assertEquals(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("지원 되는 인증 타입일시")
        class WhenSupportedGrantType {
            private OAuth2ClientDetails clientDetails;
            private OAuth2TokenRequest tokenRequest;
            private OAuth2AccessTokenGrantService codeTokenGranter;
            private OAuth2AccessTokenDetails token;

            @BeforeEach
            void setup() {
                this.clientDetails = mock(OAuth2ClientDetails.class);
                this.tokenRequest = mock(OAuth2TokenRequest.class);
                this.codeTokenGranter = mock(OAuth2AccessTokenGrantService.class);
                this.token = mock(OAuth2AccessTokenDetails.class);

                when(this.tokenRequest.getGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
                when(this.codeTokenGranter.grant(clientDetails, tokenRequest)).thenReturn(token);

                accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.AUTHORIZATION_CODE, codeTokenGranter);
                accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.CLIENT_CREDENTIALS, mock(OAuth2AccessTokenGrantService.class));
                accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.REFRESH_TOKEN, mock(OAuth2AccessTokenGrantService.class));
                accessTokenGranter.putTokenGranterMap(AuthorizationGrantType.PASSWORD, mock(OAuth2AccessTokenGrantService.class));
            }

            @Test
            @DisplayName("인증 타입에 대응되는 토큰 부여 클래스를 찾아 토큰을 생성한다.")
            void shouldCreateTokenByLookingTokenGranterCorrespondingGrantType() {
                accessTokenGranter.grant(clientDetails, tokenRequest);

                verify(codeTokenGranter, times(1)).grant(clientDetails, tokenRequest);
            }

            @Test
            @DisplayName("토큰 부여 클래스에서 생섣된 토큰을 반환해야 한다.")
            void shouldReturnsTokenByTokenGranter() {
                OAuth2AccessTokenDetails accessToken = accessTokenGranter.grant(clientDetails, tokenRequest);

                assertEquals(token, accessToken);
            }
        }
    }

}