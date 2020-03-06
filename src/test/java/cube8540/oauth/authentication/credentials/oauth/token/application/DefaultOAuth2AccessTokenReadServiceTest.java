package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenExpiredException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.util.Optional;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockUser;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockUserDetailsService;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 토큰 부여 서비스 테스트")
class DefaultOAuth2AccessTokenReadServiceTest {
    private static final String RAW_DIFFERENT_CLIENT = "DIFFERENT-CLIENT";
    private static final OAuth2ClientId DIFFERENT_CLIENT = new OAuth2ClientId(RAW_DIFFERENT_CLIENT);

    @Nested
    @DisplayName("엑세스 토큰 읽기")
    class ReadAccessToken {

        @Nested
        @DisplayName("저장소에서 엑세스 토큰을 찾을 수 없을시")
        class WhenAccessTokenNotFound {
            private DefaultOAuth2AccessTokenReadService service;

            @BeforeEach
            void setup() {
                OAuth2AccessTokenRepository repository = mockAccessTokenRepository().emptyAccessToken().build();
                this.service = new DefaultOAuth2AccessTokenReadService(repository, mockUserDetailsService().build());
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
                private DefaultOAuth2AccessTokenReadService service;

                @BeforeEach
                void setup() {
                    OAuth2AuthorizedAccessToken accessToken = mockAccessToken().configDefault().configExpired().build();
                    OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(accessToken).build();
                    this.service = new DefaultOAuth2AccessTokenReadService(repository, mockUserDetailsService().build());
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

                @BeforeEach
                void setup() {
                    Authentication authentication = mock(Authentication.class);
                    when(authentication.getName()).thenReturn(RAW_CLIENT);
                    when(accessToken.getClient()).thenReturn(DIFFERENT_CLIENT);
                    when(accessToken.isExpired()).thenReturn(false);
                    when(accessTokenRepository.findById(TOKEN_ID)).thenReturn(Optional.of(accessToken));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }

                @Test
                @DisplayName("InvalidClientException이 발생해야 하며 에러 코드는 INVALID_CLIENT 이어야 한다.")
                void shouldThrowsInvalidClientExceptionAndErrorCodeIsInvalidClient() {
                    String errorCode = assertThrows(InvalidClientException.class, () -> service.readAccessToken(RAW_TOKEN_ID))
                            .getError().getErrorCode();
                    assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, errorCode);
                }

                @AfterEach
                void after() {
                    SecurityContextHolder.clearContext();
                }
            }

            @Nested
            @DisplayName("엑세스 토큰이 만료되지 않았으며 엑세스 토큰의 클라이언트 정보와 요청한 클라이언트 정보가 일치할시")
            class WhenAccessTokenIsNotExpiredAndSameAccessTokensClientAndRequestingClient {

                @Nested
                @DisplayName("엑세스 토큰의 리플래시 토큰이 null 일시")
                class WhenAccessTokensRefreshTokenIsNull {
                    private DefaultOAuth2AccessTokenReadService service;

                    @BeforeEach
                    void setup() {
                        OAuth2AuthorizedAccessToken accessToken = mockAccessToken()
                                .configDefault().configNotExpired().configEmptyRefreshToken().build();
                        OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(accessToken).build();
                        this.service = new DefaultOAuth2AccessTokenReadService(repository, mockUserDetailsService().build());
                    }

                    @Test
                    @DisplayName("리플래시 토큰 정보는 null 로 반환해야 한다.")
                    void shouldReturnsRefreshTokenIsNull() {
                        OAuth2AccessTokenDetails accessToken = service.readAccessToken(RAW_ACCESS_TOKEN_ID);

                        assertNull(accessToken.getRefreshToken());
                    }
                }

                @Nested
                @DisplayName("엑세스 토큰의 추가 확장 정보가 null 일시")
                class WhenAccessTokenAdditionalInformationIsNull {
                    private DefaultOAuth2AccessTokenReadService service;

                    @BeforeEach
                    void setup() {
                        OAuth2AuthorizedAccessToken accessToken = mockAccessToken()
                                .configDefault().configNotExpired().configNullAdditionalInfo().build();
                        OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(accessToken).build();
                        this.service = new DefaultOAuth2AccessTokenReadService(repository, mockUserDetailsService().build());
                    }

                    @Test
                    @DisplayName("추가 확장 정보는 null 로 반환해야 한다.")
                    void shouldReturnsAdditionalInformationIsNull() {
                        OAuth2AccessTokenDetails accessToken = service.readAccessToken(RAW_ACCESS_TOKEN_ID);

                        assertNull(accessToken.getAdditionalInformation());
                    }
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
            private DefaultOAuth2AccessTokenReadService service;

            @BeforeEach
            void setup() {
                OAuth2AccessTokenRepository repository = mockAccessTokenRepository().emptyAccessToken().build();
                this.service = new DefaultOAuth2AccessTokenReadService(repository, mockUserDetailsService().build());
            }

            @Test
            @DisplayName("OAuth2AccessTokenNotFoundException 이 발생해야 한다.")
            void shouldThrowsOAuth2AccessTokenNotFoundException() {
                assertThrows(OAuth2AccessTokenNotFoundException.class, () -> service.readAccessTokenUser(RAW_ACCESS_TOKEN_ID));
            }
        }

        @Nested
        @DisplayName("검색된 토큰의 클라이언트 정보와 요청한 클라이언트 정보가 일치하지 않을시")
        class WhenDifferentSearchedAccessTokenClientAndRequestingClient {

            @BeforeEach
            void setup() {
                OAuth2AuthorizedAccessToken accessToken = mock(OAuth2AuthorizedAccessToken.class);

                when(accessToken.getUsername()).thenReturn(EMAIL);
                when(accessToken.getClient()).thenReturn(DIFFERENT_CLIENT);
                when(accessTokenRepository.findById(TOKEN_ID)).thenReturn(Optional.of(accessToken));

                Authentication authentication = mock(Authentication.class);
                when(authentication.getName()).thenReturn(RAW_CLIENT);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            @Test
            @DisplayName("InvalidClientException이 발생해야 하며 에러 코드는 INVALID_CLIENT 이어야 한다.")
            void shouldThrowsInvalidClientExceptionAndErrorCodeIsInvalidClient() {
                String errorCode = assertThrows(InvalidClientException.class, () -> service.readAccessTokenUser(RAW_TOKEN_ID))
                        .getError().getErrorCode();
                assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, errorCode);
            }

            @AfterEach
            void after() {
                SecurityContextHolder.clearContext();
            }
        }

        @Test
        @DisplayName("토큰의 소유자를 검색하여 반환 해야 한다.")
        void shouldReturnAccessTokenOwner() {
            UserDetails user = service.readAccessTokenUser(RAW_TOKEN_ID);
            assertEquals(userDetails, user);
        }

        @Nested
        @DisplayName("검색하려는 엑세스 토큰이 저장소에 저장되어 있을시")
        class WhenReadAccessTokenIsRegisteredInRepository {

            @Nested
            @DisplayName("검색된 유저 객체가 CredentialsContainer 를 구현하고 있을시")
            class WhenUserDetailsObjectImplementCredentialsContainer {
                private User userDetails;
                private DefaultOAuth2AccessTokenReadService service;

                @BeforeEach
                void setup() {
                    this.userDetails = mockUser();

                    OAuth2AuthorizedAccessToken accessToken = mockAccessToken().configDefault().build();
                    OAuth2AccessTokenRepository repository = mockAccessTokenRepository().registerAccessToken(accessToken).build();
                    UserDetailsService userDetailsService = mockUserDetailsService().registerUser(userDetails).build();

                    this.service = new DefaultOAuth2AccessTokenReadService(repository, userDetailsService);
                }

                @Test
                @DisplayName("검색된 유저 객체에서 민감한 정보는 삭제해야 한다.")
                void shouldErasedCredentials() {
                    service.readAccessTokenUser(RAW_ACCESS_TOKEN_ID);
                    verify(userDetails, times(1)).eraseCredentials();
                }
            }
        }
    }
}
