package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenEnhancer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 토큰 부여 추상 클래스 테스트")
class AbstractOAuth2TokenGranterTest {

    @Nested
    @DisplayName("엑세스 토큰 부여 테스트")
    class GrantAccessToken {

        @Nested
        @DisplayName("엑세스 토큰의 소유자가 요청한 클라이언트로 이미 인증을 받은 상태일시")
        class WhenAccessTokenUserAlreadyAuthenticationByRequestingClient extends GrantAccessTokenAssertSetup {
            private OAuth2AuthorizedAccessToken existsAccessToken;

            @Override
            protected void configRepository(OAuth2TokenApplicationTestHelper.MockAccessTokenRepository repository) {
                this.existsAccessToken = OAuth2TokenApplicationTestHelper.mockAccessToken().configDefault().build();
                repository.registerAuthentication(existsAccessToken);
            }

            @Test
            @DisplayName("저장소에서 반환된 엑세스 토큰을 삭제해야 한다.")
            void shouldRemoveReturnsAccessToken() {
                granter.grant(clientDetails, tokenRequest);

                verify(repository, times(1)).delete(existsAccessToken);
            }
        }

        @Nested
        @DisplayName("엑세스 토큰이 리플래시 토큰을 가지고 있지 않을시")
        class WhenAccessTokenNotHaveRefreshToken extends GrantAccessTokenAssertSetup {

            @Override
            protected void configAccessToken(OAuth2TokenApplicationTestHelper.MockAccessToken accessToken) {
                accessToken.configEmptyRefreshToken().build();
            }

            @Test
            @DisplayName("리플래시 토큰은 null 로 반환해야 한다.")
            void shouldReturnsRefreshTokenNull() {
                OAuth2AccessTokenDetails tokenDetails = granter.grant(clientDetails, tokenRequest);

                assertNull(tokenDetails.getRefreshToken());
            }
        }

        @Nested
        @DisplayName("엑세스 토큰이 리플레시 토큰을 가지고 있을시")
        class WhenAccessTokenHaveRefreshToken extends GrantAccessTokenAssertSetup {
            @Override
            protected void configAccessToken(OAuth2TokenApplicationTestHelper.MockAccessToken accessToken) {
                accessToken.configRefreshToken(OAuth2TokenApplicationTestHelper.mockRefreshToken().configDefault().build());
            }

            @Test
            @DisplayName("저장된 엑세스 토큰의 리플래시 토큰의 정보를 반환해야 한다.")
            void shouldReturnsRegisteredAccessTokensRefreshTokenInfo() {
                OAuth2AccessTokenDetails token = granter.grant(clientDetails, tokenRequest);

                Assertions.assertEquals(OAuth2TokenApplicationTestHelper.RAW_REFRESH_TOKEN_ID, token.getRefreshToken().getTokenValue());
                Assertions.assertEquals(OAuth2TokenApplicationTestHelper.EXPIRATION_DATETIME, token.getRefreshToken().getExpiration());
                Assertions.assertEquals(OAuth2TokenApplicationTestHelper.EXPIRATION_IN, token.getExpiresIn());
            }
        }
    }

    private static abstract class GrantAccessTokenAssertSetup {
        protected OAuth2AuthorizedAccessToken accessToken;
        protected OAuth2AccessTokenRepository repository;
        protected OAuth2ClientDetails clientDetails;
        protected OAuth2TokenRequest tokenRequest;
        protected OAuth2TokenEnhancer enhancer;

        protected AbstractOAuth2TokenGranter granter;

        @BeforeEach
        void setup() {
            OAuth2TokenApplicationTestHelper.MockAccessTokenRepository mockRepository = OAuth2TokenApplicationTestHelper.mockAccessTokenRepository();
            configRepository(mockRepository);
            OAuth2TokenApplicationTestHelper.MockAccessToken mockAccessToken = OAuth2TokenApplicationTestHelper.mockAccessToken().configDefault();
            configAccessToken(mockAccessToken);

            this.accessToken = mockAccessToken.build();
            this.repository = mockRepository.build();
            this.clientDetails = mock(OAuth2ClientDetails.class);
            this.tokenRequest = mock(OAuth2TokenRequest.class);
            this.granter = mock(AbstractOAuth2TokenGranter.class, CALLS_REAL_METHODS);
            this.enhancer = OAuth2TokenApplicationTestHelper.mockTokenEnhancer();

            this.granter.setTokenRepository(repository);
            this.granter.setTokenEnhancer(enhancer);

            when(granter.createAccessToken(clientDetails, tokenRequest)).thenReturn(accessToken);
        }

        @Test
        @DisplayName("생성된 엑세스 토큰을 저장해야 한다.")
        void shouldSaveAccessTokenCreatedByFactory() {
            granter.grant(clientDetails, tokenRequest);

            verify(repository, times(1)).save(accessToken);
        }

        @Test
        @DisplayName("설정된 Enhancer 를 사용한 후 저장해야 한다.")
        void shouldSaveBeforeUsingEnhancer() {
            granter.grant(clientDetails, tokenRequest);

            InOrder inOrder = Mockito.inOrder(repository, enhancer);
            inOrder.verify(enhancer, times(1)).enhance(accessToken);
            inOrder.verify(repository, times(1)).save(accessToken);
        }

        @Test
        @DisplayName("저장된 토큰의 정보를 반환해야 한다.")
        void shouldReturnsRegisteredTokenInfo() {
            OAuth2AccessTokenDetails token = granter.grant(clientDetails, tokenRequest);

            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.RAW_ACCESS_TOKEN_ID, token.getTokenValue());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.EXPIRATION_DATETIME, token.getExpiration());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.EXPIRATION_IN, token.getExpiresIn());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.CLIENT_ID, token.getClientId());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.SCOPES, token.getScopes());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.RAW_USERNAME, token.getUsername());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.ADDITIONAL_INFO, token.getAdditionalInformation());
            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.TOKEN_TYPE, token.getTokenType());
        }

        protected void configRepository(OAuth2TokenApplicationTestHelper.MockAccessTokenRepository repository) {}
        protected void configAccessToken(OAuth2TokenApplicationTestHelper.MockAccessToken accessToken) {}
    }
}
