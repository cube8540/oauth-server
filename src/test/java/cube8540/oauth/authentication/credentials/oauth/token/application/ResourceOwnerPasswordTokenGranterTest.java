package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("자원 소유자의 패스워드를 통한 토큰 부여 테스트")
class ResourceOwnerPasswordTokenGranterTest {

    private static final String RAW_REQUESTED_USERNAME = "email@email.com";
    private static final String RAW_REQUESTED_PASSWORD = "Password1234!@#$";

    private static final String RAW_TOKEN_ID = "TOKEN-ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final String RAW_REFRESH_TOKEN_ID = "REFRESH-TOKEN-ID";
    private static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final LocalDateTime TOKEN_CREATED_DATETIME = LocalDateTime.of(2020, 1, 29, 22, 57);

    private static final Integer ACCESS_TOKEN_VALIDITY_SECONDS = 600;
    private static final Integer REFRESH_TOKEN_VALIDITY_SECONDS = 6000;

    private static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("CODE-1", "CODE-2", "CODE-3"));
    private static final Set<String> CLIENT_SCOPE = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    private static final Set<OAuth2ScopeId> REQUESTED_SCOPE = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("CODE-1"),
            new OAuth2ScopeId("CODE-2"),
            new OAuth2ScopeId("CODE-3")
    ));

    private OAuth2TokenIdGenerator tokenIdGenerator;
    private OAuth2TokenIdGenerator refreshTokenIdGenerator;
    private AuthenticationManager authenticationManager;
    private ResourceOwnerPasswordTokenGranter tokenGranter;

    @BeforeEach
    void setup() {
        this.tokenIdGenerator = mock(OAuth2TokenIdGenerator.class);
        OAuth2AccessTokenRepository accessTokenRepository = mock(OAuth2AccessTokenRepository.class);
        this.refreshTokenIdGenerator = mock(OAuth2TokenIdGenerator.class);
        this.authenticationManager = mock(AuthenticationManager.class);
        this.tokenGranter = new ResourceOwnerPasswordTokenGranter(tokenIdGenerator, accessTokenRepository, authenticationManager);
    }

    @Nested
    @DisplayName("엑세스 토큰 생성")
    class CreateAccessToken {

        private OAuth2ClientDetails clientDetails;
        private OAuth2TokenRequest tokenRequest;

        private OAuth2RequestValidator validator;

        @BeforeEach
        void setup() {
            this.clientDetails = mock(OAuth2ClientDetails.class);
            this.tokenRequest = mock(OAuth2TokenRequest.class);
            this.validator = mock(OAuth2RequestValidator.class);

            when(clientDetails.clientId()).thenReturn(RAW_CLIENT_ID);
            when(clientDetails.scope()).thenReturn(CLIENT_SCOPE);
            when(clientDetails.accessTokenValiditySeconds()).thenReturn(ACCESS_TOKEN_VALIDITY_SECONDS);
            when(clientDetails.refreshTokenValiditySeconds()).thenReturn(REFRESH_TOKEN_VALIDITY_SECONDS);

            when(tokenRequest.scopes()).thenReturn(RAW_SCOPES);
            when(tokenRequest.username()).thenReturn(RAW_REQUESTED_USERNAME);
            when(tokenRequest.password()).thenReturn(RAW_REQUESTED_PASSWORD);

            tokenGranter.setTokenRequestValidator(this.validator);

            Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
            tokenGranter.setClock(clock);
        }

        @Nested
        @DisplayName("요청 객체에서 유저 아이디를 찾을 수 없을시")
        class WhenNotfoundUsernameParameter {

            @BeforeEach
            void setup() {
                when(tokenRequest.username()).thenReturn(null);
            }

            @Test
            @DisplayName("InvalidRequestException이 발생해야 한다.")
            void shouldInvalidRequestException() {
                assertThrows(InvalidRequestException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));
            }
        }

        @Nested
        @DisplayName("요청 객체에서 패스워드를 찾을 수 없을시")
        class WhenNotfoundPasswordParameter {

            @BeforeEach
            void setup() {
                when(tokenRequest.password()).thenReturn(null);
            }

            @Test
            @DisplayName("InvalidRequestException이 발생해야 한다.")
            void shouldInvalidRequestException() {
                assertThrows(InvalidRequestException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));
            }
        }

        @Nested
        @DisplayName("요청 받은 스코프가 유효하지 않을시")
        class WhenScopeNotAllowed {

            @BeforeEach
            void setup() {
                when(validator.validateScopes(clientDetails, RAW_SCOPES)).thenReturn(false);
            }

            @Test
            @DisplayName("InvalidGrantExcetpion이 발생해야 한다.")
            void shouldThrowsInvalidGrantException() {
                assertThrows(InvalidGrantException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));
            }
        }

        @Nested
        @DisplayName("요청 정보가 유효할시")
        class WhenRequestParameterAllowed {

            private String rawAuthenticationUsername = "AUTHENTICATED_USERNAME";
            private UserEmail authenticationUsername = new UserEmail(rawAuthenticationUsername);

            @BeforeEach
            void setup() {
                UsernamePasswordAuthenticationToken usernamePasswordToken =
                        new UsernamePasswordAuthenticationToken(RAW_REQUESTED_USERNAME, RAW_REQUESTED_PASSWORD);
                Authentication authentication = mock(Authentication.class);

                when(validator.validateScopes(clientDetails, RAW_SCOPES)).thenReturn(true);
                when(tokenIdGenerator.generateTokenValue()).thenReturn(TOKEN_ID);
                when(authenticationManager.authenticate(usernamePasswordToken)).thenReturn(authentication);
                when(authentication.getName()).thenReturn(rawAuthenticationUsername);
            }

            @Test
            @DisplayName("요청 받은 아이디와 비밀번호로 유저 인증을 해야 한다.")
            void shouldAuthenticationViaRequestingUsernameAndPassword() {
                ArgumentCaptor<Authentication> authenticationTokenCaptor = ArgumentCaptor.forClass(Authentication.class);

                tokenGranter.createAccessToken(clientDetails, tokenRequest);
                verify(authenticationManager, times(1)).authenticate(authenticationTokenCaptor.capture());
                assertEquals(UsernamePasswordAuthenticationToken.class, authenticationTokenCaptor.getValue().getClass());
                assertEquals(RAW_REQUESTED_USERNAME, authenticationTokenCaptor.getValue().getPrincipal());
                assertEquals(RAW_REQUESTED_PASSWORD, authenticationTokenCaptor.getValue().getCredentials());
            }

            @Nested
            @DisplayName("계정 인증에 실패했을시")
            class WhenAuthenticationFails {

                @BeforeEach
                void setup() {
                    when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("bad credentials"));
                }

                @Test
                @DisplayName("InvalidGrantException이 발생해야 한다.")
                void shouldInvalidGrantException() {
                    assertThrows(InvalidGrantException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));
                }
            }

            @Nested
            @DisplayName("계정 상태가 유효하지 않을시")
            class WhenAccountStatusNotAllowed {

                @BeforeEach
                void setup() {
                    when(authenticationManager.authenticate(any())).thenThrow(new TestAccountStatusException("account not allowed"));
                }

                @Test
                @DisplayName("InvalidGrantException이 발생해야 한다.")
                void shouldInvalidGrantException() {
                    assertThrows(InvalidGrantException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));
                }
            }

            @Test
            @DisplayName("토큰 아이디는 토큰 아이디 생성기에서 생성된 아이디어야 한다.")
            void shouldTokenIdIsCreatedByTokenGenerator() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(TOKEN_ID, accessToken.getTokenId());
            }

            @Test
            @DisplayName("토큰의 클라이언트 아이디는 ClientDetails에 저장된 클라이언트 아이디어야한다.")
            void shouldClientIdIsStoredInClientDetails() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(CLIENT_ID, accessToken.getClient());
            }

            @Test
            @DisplayName("토큰에 저장된 스코프는 요청 객체에 담긴 스코프어야 한다.")
            void shouldScopeIsRequestedScope() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(REQUESTED_SCOPE, accessToken.getScope());
            }

            @Test
            @DisplayName("토큰에 저장된 유저 아이디는 인증받은 유저의 아이디어야 한다.")
            void shouldUsernameIsAuthenticationUsername() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(authenticationUsername, accessToken.getEmail());
            }

            @Test
            @DisplayName("토큰의 인증 타입은 자원 소유자 패스워드 인증 방식 이어야 한다.")
            void shouldGrantTypeIsResourceOwnerPasswordGrantType() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(AuthorizationGrantType.PASSWORD, accessToken.getTokenGrantType());
            }

            @Test
            @DisplayName("리플레시 토큰 아이디는 토큰 아이디 생성기에서 생성된 아이디어야 한다.")
            void shouldRefreshTokenIdIsCreatedByTokenIdGenerator() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(TOKEN_ID, accessToken.getRefreshToken().getTokenId());
            }

            @Test
            @DisplayName("토큰의 유효시간이 설정되어 있어야 한다.")
            void shouldSetTokenValidity() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), accessToken.getExpiration());
            }

            @Test
            @DisplayName("리플래시 토큰의 유효시간이 설정되어 있어야 한다.")
            void shouldSetRefreshTokenValidity() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), accessToken.getRefreshToken().getExpiration());
            }

            @Nested
            @DisplayName("리플래시 토큰 아이디 생성자가 설정되어 있을시")
            class WhenSetRefreshTokenId {

                @BeforeEach
                void setup() {
                    tokenGranter.setRefreshTokenIdGenerator(refreshTokenIdGenerator);

                    when(refreshTokenIdGenerator.generateTokenValue()).thenReturn(REFRESH_TOKEN_ID);
                }

                @Test
                @DisplayName("리플래스 토큰의 아이디는 리플래시 토큰 아이디 생성자가 생성한 아이디어야 한다.")
                void shouldRefreshTokenIdIsCreatedByRefreshTokenIdGenerator() {
                    OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                }

                @AfterEach
                void after() {
                    tokenGranter.setRefreshTokenIdGenerator(null);
                }
            }

            @Nested
            @DisplayName("요청 스코프가 null이거나 비어있을시")
            class WhenRequestScopeNullOrEmpty {

                @Nested
                @DisplayName("요청 스코프가 null일시")
                class WhenRequestScopeNull {
                    @BeforeEach
                    void setup() {
                        when(tokenRequest.scopes()).thenReturn(null);
                        when(validator.validateScopes(clientDetails, null)).thenReturn(true);
                    }

                    @Test
                    @DisplayName("토큰의 스코프는 ClientDetails에 저장된 스코프어야 한다.")
                    void shouldScopeIsStoredInClientDetails() {
                        Set<OAuth2ScopeId> exceptedScopes = CLIENT_SCOPE.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

                        OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);
                        assertEquals(exceptedScopes, accessToken.getScope());
                    }
                }

                @Nested
                @DisplayName("요청 스코프가 비어있을시")
                class WhenRequestEmptyScope {
                    @BeforeEach
                    void setup() {
                        when(tokenRequest.scopes()).thenReturn(Collections.emptySet());
                        when(validator.validateScopes(clientDetails, Collections.emptySet())).thenReturn(true);
                    }

                    @Test
                    @DisplayName("토큰의 스코프는 ClientDetails에 저장된 스코프어야 한다.")
                    void shouldScopeIsStoredInClientDetails() {
                        Set<OAuth2ScopeId> exceptedScopes = CLIENT_SCOPE.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

                        OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);
                        assertEquals(exceptedScopes, accessToken.getScope());
                    }
                }
            }
        }
    }

    private static final class TestAccountStatusException extends AccountStatusException {

        public TestAccountStatusException(String msg) {
            super(msg);
        }
    }
}
