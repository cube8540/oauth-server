package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.exception.TokenAccessDeniedException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_DIFFERENT_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAuthentication;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("유저 인증 기준 토큰 삭제 서비스")
class UserAuthenticationBaseTokenRevokerTest {

    @Nested
    @DisplayName("토큰 삭제")
    class TokenRevoke {

        @Nested
        @DisplayName("삭제하려는 토큰이 저장소에 등록되어 있지 않을시")
        class RevokeTokenIsNotRegisteredInRepository {
            private UserAuthenticationBaseTokenRevoker revoker;

            @BeforeEach
            void setup() {
                this.revoker = new UserAuthenticationBaseTokenRevoker(mockAccessTokenRepository().emptyAccessToken().build());
            }

            @Test
            @DisplayName("OAuth2AccessTokenNotFoundException 이 발생해야 한다.")
            void shouldThrowsAccessTokenNotfoundException() {
                assertThrows(OAuth2AccessTokenNotFoundException.class, () -> revoker.revoke(RAW_ACCESS_TOKEN_ID));
            }
        }

        @Nested
        @DisplayName("삭제하려는 토큰이 저장소에 등록되어 있을시")
        class RevokeTokenIsRegisteredInRepository {

            @Nested
            @DisplayName("검색된 엑세스 토큰의 소유자와 요청한 유저의 정보가 일치하지 않을시")
            class WhenDifferentSearchedAccessTokensUsernameAndRequestingUsername {
                private UserAuthenticationBaseTokenRevoker revoker;

                @BeforeEach
                void setup() {
                    OAuth2AuthorizedAccessToken token = mockAccessToken().configDefault().build();
                    OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(token).build();

                    this.revoker = new UserAuthenticationBaseTokenRevoker(repository);

                    SecurityContextHolder.getContext().setAuthentication(mockAuthentication(RAW_DIFFERENT_USERNAME));
                }

                @Test
                @DisplayName("AuthenticationDeniedException 이 발생해야 하며 에러 코드는 ACCESS_DENIED 이어야 한다.")
                void shouldThrowsAuthenticationDeniedException() {
                    String errorCode = assertThrows(TokenAccessDeniedException.class, () -> revoker.revoke(RAW_ACCESS_TOKEN_ID))
                            .getCode();
                    assertEquals(ErrorCodes.ACCESS_DENIED, errorCode);
                }
            }

            @Nested
            @DisplayName("검색된 엑세스 토큰의 소유자와 요청한 유저의 정보가 일치할시")
            class WhenSameSearchedAccessTokenUserAndRequestingUser {
                private OAuth2AuthorizedAccessToken token;
                private OAuth2AccessTokenRepository repository;
                private UserAuthenticationBaseTokenRevoker revoker;

                @BeforeEach
                void setup() {
                    this.token = mockAccessToken().configDefault().build();
                    this.repository = mockAccessTokenRepository().registerAccessToken(token).build();
                    this.revoker = new UserAuthenticationBaseTokenRevoker(repository);

                    SecurityContextHolder.getContext().setAuthentication(mockAuthentication(RAW_USERNAME));
                }

                @Test
                @DisplayName("저장소의 토큰을 삭제해야 한다.")
                void shouldRemoveToken() {
                    revoker.revoke(RAW_ACCESS_TOKEN_ID);

                    verify(repository, times(1)).delete(token);
                }
            }
        }
    }
}