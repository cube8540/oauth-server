package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessTokenRepository;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 토큰 삭제 서비스")
class DefaultOAuth2TokenRevokeServiceTest {

    @Nested
    @DisplayName("토큰 삭제")
    class TokenRevoke {

        @Nested
        @DisplayName("삭제하려는 토큰이 저장소에 등록되어 있지 않을시")
        class RevokeTokenIsNotRegisteredInRepository {
            private DefaultOAuth2TokenRevokeService service;

            @BeforeEach
            void setup() {
                this.service = new DefaultOAuth2TokenRevokeService(mockAccessTokenRepository().emptyAccessToken().build());
            }

            @Test
            @DisplayName("OAuth2AccessTokenNotFoundException 이 발생해야 한다.")
            void shouldOAuth2AccessTokenNotFoundException() {
                assertThrows(OAuth2AccessTokenNotFoundException.class, () -> service.revoke(RAW_ACCESS_TOKEN_ID));
            }
        }

        @Nested
        @DisplayName("삭제하려는 토큰이 저장소에 등록되어 있을시")
        class RevokeTokenIsRegisteredInRepository {
            private OAuth2AuthorizedAccessToken token;
            private OAuth2AccessTokenRepository repository;
            private DefaultOAuth2TokenRevokeService service;

            @BeforeEach
            void setup() {
                this.token = mockAccessToken().configDefault().build();
                this.repository = mockAccessTokenRepository().registerAccessToken(token).build();
                this.service = new DefaultOAuth2TokenRevokeService(repository);
            }

            @Test
            @DisplayName("저장소의 토큰을 삭제해야 한다.")
            void shouldRemoveToken() {
                service.revoke(RAW_ACCESS_TOKEN_ID);

                verify(repository, times(1)).delete(token);
            }
        }
    }

}
