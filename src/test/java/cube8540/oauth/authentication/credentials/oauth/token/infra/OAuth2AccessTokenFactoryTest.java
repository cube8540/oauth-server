package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 엑세스 토큰 팩토리 테스트")
class OAuth2AccessTokenFactoryTest {

    private OAuth2AccessTokenFactory accessTokenFactory;

    @BeforeEach
    void setup() {
        this.accessTokenFactory = new OAuth2AccessTokenFactory();
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
                assertThrows(InvalidGrantException.class, () -> accessTokenFactory.createAccessToken(clientDetails, tokenRequest));
            }
        }

        @Nested
        @DisplayName("지원 되는 인증 타입일시")
        class WhenSupportedGrantType {
            private OAuth2ClientDetails clientDetails;
            private OAuth2TokenRequest tokenRequest;
            private OAuth2TokenFactory codeTokenFactory;
            private OAuth2TokenFactory refreshTokenFactory;
            private OAuth2TokenFactory clientCredentialsTokenFactory;
            private OAuth2TokenFactory passwordTokenFactory;
            private OAuth2AuthorizedAccessToken token;

            @BeforeEach
            void setup() {
                this.clientDetails = mock(OAuth2ClientDetails.class);
                this.tokenRequest = mock(OAuth2TokenRequest.class);
                this.codeTokenFactory = mock(OAuth2TokenFactory.class);
                this.refreshTokenFactory = mock(OAuth2TokenFactory.class);
                this.clientCredentialsTokenFactory = mock(OAuth2TokenFactory.class);
                this.passwordTokenFactory = mock(OAuth2TokenFactory.class);
                this.token = mock(OAuth2AuthorizedAccessToken.class);

                when(this.tokenRequest.grantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
                when(this.codeTokenFactory.createAccessToken(clientDetails, tokenRequest)).thenReturn(token);

                accessTokenFactory.putTokenFactoryMap(AuthorizationGrantType.AUTHORIZATION_CODE, codeTokenFactory);
                accessTokenFactory.putTokenFactoryMap(AuthorizationGrantType.CLIENT_CREDENTIALS, clientCredentialsTokenFactory);
                accessTokenFactory.putTokenFactoryMap(AuthorizationGrantType.REFRESH_TOKEN, refreshTokenFactory);
                accessTokenFactory.putTokenFactoryMap(AuthorizationGrantType.PASSWORD, passwordTokenFactory);
            }

            @Test
            @DisplayName("인증 타입에 대응되는 토큰 팩토리를 찾아 토큰을 생성한다.")
            void shouldCreateTokenByLookingTokenFactoryCorrespondingGrantType() {
                accessTokenFactory.createAccessToken(clientDetails, tokenRequest);

                verify(codeTokenFactory, times(1)).createAccessToken(clientDetails, tokenRequest);
            }

            @Test
            @DisplayName("토큰 팩토리에서 생섣된 토큰을 반환해야 한다.")
            void shouldReturnsTokenByTokenFactory() {
                OAuth2AuthorizedAccessToken accessToken = accessTokenFactory.createAccessToken(clientDetails, tokenRequest);

                assertEquals(token, accessToken);
            }
        }
    }

}