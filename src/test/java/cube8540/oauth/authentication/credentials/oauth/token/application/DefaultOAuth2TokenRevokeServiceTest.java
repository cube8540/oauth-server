package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 토큰 삭제 서비스")
class DefaultOAuth2TokenRevokeServiceTest {

    private static final String RAW_TOKEN_ID = "TOKEN-ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final String RAW_CLIENT = "CLIENT";
    private static final OAuth2ClientId CLIENT = new OAuth2ClientId(RAW_CLIENT);

    private static final String RAW_DIFFERENT_CLIENT = "DIFFERENT-CLIENT";
    private static final OAuth2ClientId DIFFERENT_CLIENT = new OAuth2ClientId(RAW_DIFFERENT_CLIENT);

    private OAuth2AccessTokenRepository repository;
    private DefaultOAuth2TokenRevokeService service;

    @BeforeEach
    void setup() {
        this.repository = mock(OAuth2AccessTokenRepository.class);
        this.service = new DefaultOAuth2TokenRevokeService(repository);
    }

    @Nested
    @DisplayName("토큰 삭제")
    class TokenRevoke {

        @Nested
        @DisplayName("삭제하려는 토큰이 저장소에 등록되어 있지 않을시")
        class RevokeTokenIsNotRegisteredInRepository {

            @BeforeEach
            void setup() {
                when(repository.findById(TOKEN_ID)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("OAuth2AccessTokenNotFoundException이 발생해야 한다.")
            void shouldOAuth2AccessTokenNotFoundException() {
                assertThrows(OAuth2AccessTokenNotFoundException.class, () -> service.revoke(RAW_TOKEN_ID));
            }
        }

        @Nested
        @DisplayName("삭제하려는 토큰이 저장소에 등록되어 있을시")
        class RevokeTokenIsRegisteredInRepository {
            private OAuth2AuthorizedAccessToken token;

            @BeforeEach
            void setup() {
                this.token = mock(OAuth2AuthorizedAccessToken.class);

                when(token.getClient()).thenReturn(CLIENT);
                when(token.getTokenId()).thenReturn(TOKEN_ID);
                when(repository.findById(TOKEN_ID)).thenReturn(Optional.of(token));

                Authentication authentication = mock(Authentication.class);
                when(authentication.getName()).thenReturn(RAW_CLIENT);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            @Nested
            @DisplayName("검색된 엑세스 토큰의 클라이언트와 요청한 클라이언트의 정보가 일치하지 않을시")
            class WhenDifferentSearchedAccessTokensClientAndRequestingClient {

                @BeforeEach
                void setup() {
                    when(token.getClient()).thenReturn(DIFFERENT_CLIENT);
                }

                @Test
                @DisplayName("InvalidClientException이 발생해야 하며 에러 코드는 INVALID_CLIENT 이어야 한다.")
                void shouldThrowsInvalidClientExceptionAndErrorCodeIsInvalidClient() {
                    String errorCode = assertThrows(InvalidClientException.class, () -> service.revoke(RAW_TOKEN_ID))
                            .getError().getErrorCode();
                    assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, errorCode);
                }
            }

            @Test
            @DisplayName("저장소의 토큰을 삭제해야 한다.")
            void shouldRemoveToken() {
                service.revoke(RAW_TOKEN_ID);

                verify(repository, times(1)).delete(token);
            }
        }

        @AfterEach
        void after() {
            SecurityContextHolder.clearContext();
        }
    }

}