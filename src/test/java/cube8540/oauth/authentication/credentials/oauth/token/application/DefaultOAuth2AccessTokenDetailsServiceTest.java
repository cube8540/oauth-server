package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenExpiredException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_DIFFERENT_CLIENT;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAuthentication;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockUser;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockUserDetailsService;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 토큰 부여 서비스 테스트")
class DefaultOAuth2AccessTokenDetailsServiceTest {

    @Nested
    @DisplayName("엑세스 토큰 읽기")
    class ReadAccessToken {

        @Nested
        @DisplayName("저장소에서 엑세스 토큰을 찾을 수 없을시")
        class WhenAccessTokenNotFound {
            private DefaultOAuth2AccessTokenDetailsService service;

            @BeforeEach
            void setup() {
                OAuth2AccessTokenRepository repository = mockAccessTokenRepository().emptyAccessToken().build();
                this.service = new DefaultOAuth2AccessTokenDetailsService(repository, mockUserDetailsService().build());
            }

            @Test
            @DisplayName("OAuth2AccessTokenNotFoundException 이 발생해야 한다.")
            void shouldThrowsOAuth2AccessTokenNotFoundException() {
                assertThrows(OAuth2AccessTokenNotFoundException.class, () -> service.readAccessToken(RAW_ACCESS_TOKEN_ID));
            }
        }

        @Nested
        @DisplayName("저장소에서 엑세스 토큰을 찾았을시")
        class WhenAccessTokenFound {

            @Nested
            @DisplayName("엑세스 토큰이 만료되었을시")
            class WhenAccessTokenIsExpired {
                private DefaultOAuth2AccessTokenDetailsService service;

                @BeforeEach
                void setup() {
                    OAuth2AuthorizedAccessToken accessToken = mockAccessToken().configDefault().configExpired().build();
                    OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(accessToken).build();
                    this.service = new DefaultOAuth2AccessTokenDetailsService(repository, mockUserDetailsService().build());
                }

                @Test
                @DisplayName("OAuth2AccessTokenExpiredException 이 발생해야 한다.")
                void shouldThrowsOAuth2AccessTokenExpiredException() {
                    assertThrows(OAuth2AccessTokenExpiredException.class, () -> service.readAccessToken(RAW_ACCESS_TOKEN_ID));
                }
            }

            @Nested
            @DisplayName("엑세스 토큰의 클라이언트와 요청한 클라이언트의 정보가 일치하지 않을시")
            class WhenDifferentSearchedAccessTokensClientAndRequestingClient {
                private DefaultOAuth2AccessTokenDetailsService service;

                @BeforeEach
                void setup() {
                    OAuth2AuthorizedAccessToken accessToken = mockAccessToken().configDefault().configNotExpired().build();
                    OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(accessToken).build();
                    SecurityContextHolder.getContext().setAuthentication(mockAuthentication(RAW_DIFFERENT_CLIENT));

                    this.service = new DefaultOAuth2AccessTokenDetailsService(repository, mockUserDetailsService().build());
                }

                @Test
                @DisplayName("InvalidClientException 이 발생해야 하며 에러 코드는 INVALID_CLIENT 이어야 한다.")
                void shouldThrowsInvalidClientExceptionAndErrorCodeIsInvalidClient() {
                    String errorCode = assertThrows(InvalidClientException.class, () -> service.readAccessToken(RAW_ACCESS_TOKEN_ID))
                            .getError().getErrorCode();
                    assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, errorCode);
                }

                @AfterEach
                void after() {
                    SecurityContextHolder.clearContext();
                }
            }

            @Nested
            @DisplayName("엑세스 토큰의 리플래시 토큰이 null 일시")
            class WhenAccessTokensRefreshTokenIsNull {
                private DefaultOAuth2AccessTokenDetailsService service;

                @BeforeEach
                void setup() {
                    OAuth2AuthorizedAccessToken accessToken = mockAccessToken()
                            .configDefault().configNotExpired().configEmptyRefreshToken().build();
                    OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(accessToken).build();
                    SecurityContextHolder.getContext().setAuthentication(mockAuthentication(RAW_CLIENT_ID));

                    this.service = new DefaultOAuth2AccessTokenDetailsService(repository, mockUserDetailsService().build());
                }

                @Test
                @DisplayName("리플래시 토큰 정보는 null 로 반환해야 한다.")
                void shouldReturnsRefreshTokenIsNull() {
                    OAuth2AccessTokenDetails accessToken = service.readAccessToken(RAW_ACCESS_TOKEN_ID);

                    assertNull(accessToken.getRefreshToken());
                }

                @AfterEach
                void after() {
                    SecurityContextHolder.clearContext();
                }
            }

            @Nested
            @DisplayName("엑세스 토큰의 추가 확장 정보가 null 일시")
            class WhenAccessTokenAdditionalInformationIsNull {
                private DefaultOAuth2AccessTokenDetailsService service;

                @BeforeEach
                void setup() {
                    OAuth2AuthorizedAccessToken accessToken = mockAccessToken()
                            .configDefault().configNotExpired().configNullAdditionalInfo().build();
                    OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(accessToken).build();
                    SecurityContextHolder.getContext().setAuthentication(mockAuthentication(RAW_CLIENT_ID));

                    this.service = new DefaultOAuth2AccessTokenDetailsService(repository, mockUserDetailsService().build());
                }

                @Test
                @DisplayName("추가 확장 정보는 null 로 반환해야 한다.")
                void shouldReturnsAdditionalInformationIsNull() {
                    OAuth2AccessTokenDetails accessToken = service.readAccessToken(RAW_ACCESS_TOKEN_ID);

                    assertNull(accessToken.getAdditionalInformation());
                }

                @AfterEach
                void after() {
                    SecurityContextHolder.clearContext();
                }
            }
        }
    }

    @Nested
    @DisplayName("엑세스 토큰의 유저 검색")
    class ReadAccessTokenUser {

        @Nested
        @DisplayName("검색하려는 엑세스 토큰의 저장소에 저장되어 있지 않을시")
        class WhenReadAccessTokenIsNotRegisteredInRepository {
            private DefaultOAuth2AccessTokenDetailsService service;

            @BeforeEach
            void setup() {
                OAuth2AccessTokenRepository repository = mockAccessTokenRepository().emptyAccessToken().build();
                this.service = new DefaultOAuth2AccessTokenDetailsService(repository, mockUserDetailsService().build());
            }

            @Test
            @DisplayName("OAuth2AccessTokenNotFoundException 이 발생해야 한다.")
            void shouldThrowsOAuth2AccessTokenNotFoundException() {
                assertThrows(OAuth2AccessTokenNotFoundException.class, () -> service.readAccessTokenUser(RAW_ACCESS_TOKEN_ID));
            }
        }

        @Nested
        @DisplayName("검색하려는 엑세스 토큰이 저장소에 저장되어 있을시")
        class WhenReadAccessTokenIsRegisteredInRepository {

            @Nested
            @DisplayName("검색된 토큰의 클라이언트 정보와 요청한 클라이언트 정보가 일치하지 않을시")
            class WhenDifferentSearchedAccessTokenClientAndRequestingClient {
                private DefaultOAuth2AccessTokenDetailsService service;

                @BeforeEach
                void setup() {
                    OAuth2AuthorizedAccessToken accessToken = mockAccessToken().configDefault().build();
                    OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(accessToken).build();
                    SecurityContextHolder.getContext().setAuthentication(mockAuthentication(RAW_DIFFERENT_CLIENT));

                    this.service = new DefaultOAuth2AccessTokenDetailsService(repository, mockUserDetailsService().build());
                }

                @Test
                @DisplayName("InvalidClientException 이 발생해야 하며 에러 코드는 INVALID_CLIENT 이어야 한다.")
                void shouldThrowsInvalidClientExceptionAndErrorCodeIsInvalidClient() {
                    String errorCode = assertThrows(InvalidClientException.class, () -> service.readAccessTokenUser(RAW_ACCESS_TOKEN_ID))
                            .getError().getErrorCode();
                    assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, errorCode);
                }

                @AfterEach
                void after() {
                    SecurityContextHolder.clearContext();
                }
            }

            @Nested
            @DisplayName("검색된 유저 객체가 CredentialsContainer 를 구현하고 있을시")
            class WhenUserDetailsObjectImplementCredentialsContainer {
                private User userDetails;
                private DefaultOAuth2AccessTokenDetailsService service;

                @BeforeEach
                void setup() {
                    this.userDetails = mockUser();

                    OAuth2AuthorizedAccessToken accessToken = mockAccessToken().configDefault().build();
                    OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(accessToken).build();
                    UserDetailsService userDetailsService = mockUserDetailsService().registerUser(userDetails).build();
                    SecurityContextHolder.getContext().setAuthentication(mockAuthentication(RAW_CLIENT_ID));

                    this.service = new DefaultOAuth2AccessTokenDetailsService(repository, userDetailsService);
                }

                @Test
                @DisplayName("검색된 유저 객체에서 민감한 정보는 삭제해야 한다.")
                void shouldErasedCredentials() {
                    service.readAccessTokenUser(RAW_ACCESS_TOKEN_ID);
                    verify(userDetails, times(1)).eraseCredentials();
                }

                @AfterEach
                void after() {
                    SecurityContextHolder.clearContext();
                }
            }
        }
    }
}