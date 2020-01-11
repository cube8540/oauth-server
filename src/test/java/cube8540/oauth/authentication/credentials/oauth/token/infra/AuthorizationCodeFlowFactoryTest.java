package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.code.application.OAuth2AuthorizationCodeService;
import cube8540.oauth.authentication.credentials.oauth.code.domain.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.code.domain.OAuth2AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("인증 코드를 통한 토큰 생성 테스트")
class AuthorizationCodeFlowFactoryTest {
    private static final String RAW_CODE = "CODE";
    private static final AuthorizationCode CODE = new AuthorizationCode(RAW_CODE);

    private static final String RAW_TOKEN_ID = "TOKEN-ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final String RAW_REFRESH_TOKEN_ID = "REFRESH-TOKEN-ID";
    private static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final URI REDIRECT_URI = URI.create("http://localhost:8080");

    private static final UserEmail STORED_EMAIL = new UserEmail("email@email.com");

    private static final Integer ACCESS_TOKEN_VALIDITY_SECONDS = 600;
    private static final Integer REFRESH_TOKEN_VALIDITY_SECONDS = 6000;

    private static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("CODE-1", "CODE-2", "CODE-3"));
    private static final Set<OAuth2ScopeId> STORED_SCOPES = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("SCOPE-ID-1"),
            new OAuth2ScopeId("SCOPE-ID-2"),
            new OAuth2ScopeId("SCOPE-ID-3")
    ));

    private OAuth2TokenIdGenerator tokenIdGenerator;
    private OAuth2TokenIdGenerator refreshTokenIdGenerator;
    private OAuth2AuthorizationCodeService authorizationCodeService;
    private AuthorizationCodeFlowTokenFactory granter;

    @BeforeEach
    void setup() {
        this.tokenIdGenerator = mock(OAuth2TokenIdGenerator.class);
        this.refreshTokenIdGenerator = mock(OAuth2TokenIdGenerator.class);
        this.authorizationCodeService = mock(OAuth2AuthorizationCodeService.class);

        this.granter = new AuthorizationCodeFlowTokenFactory(tokenIdGenerator, authorizationCodeService);
    }

    @Nested
    @DisplayName("액세스 토큰 생성")
    class CreateAccessToken {

        private OAuth2ClientDetails clientDetails;
        private OAuth2TokenRequest tokenRequest;

        private OAuth2AuthorizationCode authorizationCode;

        @BeforeEach
        void setup() {
            this.clientDetails = mock(OAuth2ClientDetails.class);
            this.tokenRequest = mock(OAuth2TokenRequest.class);
            this.authorizationCode = mock(OAuth2AuthorizationCode.class);

            when(clientDetails.accessTokenValiditySeconds()).thenReturn(ACCESS_TOKEN_VALIDITY_SECONDS);
            when(clientDetails.refreshTokenValiditySeconds()).thenReturn(REFRESH_TOKEN_VALIDITY_SECONDS);

            when(tokenRequest.clientId()).thenReturn(RAW_CLIENT_ID);
            when(tokenRequest.scopes()).thenReturn(RAW_SCOPES);
            when(tokenRequest.code()).thenReturn(RAW_CODE);
            when(tokenRequest.redirectURI()).thenReturn(REDIRECT_URI);

            when(authorizationCode.getCode()).thenReturn(CODE);
            when(authorizationCode.getClientId()).thenReturn(CLIENT_ID);
            when(authorizationCode.getEmail()).thenReturn(STORED_EMAIL);
            when(authorizationCode.getApprovedScopes()).thenReturn(STORED_SCOPES);
        }

        @Nested
        @DisplayName("코드를 찾을 수 없을시")
        class WhenNotFoundAuthorizationCode {

            @BeforeEach
            void setup() {
                when(authorizationCodeService.consume(CODE)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("InvalidRequestException이 발생해야 한다.")
            void shouldThrowsInvalidRequestException() {
                assertThrows(InvalidRequestException.class, () -> granter.createAccessToken(clientDetails, tokenRequest));
            }
        }

        @Nested
        @DisplayName("코드를 찾을 수 있을시")
        class WhenFoundAuthorizationCode {

            @BeforeEach
            void setup() {
                when(authorizationCodeService.consume(CODE)).thenReturn(Optional.of(authorizationCode));
                when(tokenIdGenerator.generateTokenValue()).thenReturn(TOKEN_ID);
            }

            @Test
            @DisplayName("인증 코드를 통해 요청 정보에 대한 유효성 검사를 해야 한다.")
            void shouldValidationTestViaAuthorizationCode() {
                ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

                granter.createAccessToken(clientDetails, tokenRequest);
                verify(authorizationCode, times(1)).validateWithAuthorizationRequest(requestCaptor.capture());
                assertEquals(REDIRECT_URI, requestCaptor.getValue().redirectURI());
                assertEquals(RAW_CLIENT_ID, requestCaptor.getValue().clientId());
                assertEquals(RAW_SCOPES, requestCaptor.getValue().approvedScopes());
            }

            @Test
            @DisplayName("토큰의 아이디는 토큰 아이디 생성기에서 생성된 토큰 아이디어야 한다.")
            void shouldTokenIdIsCreatedByTokenGenerator() {
                OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(TOKEN_ID, accessToken.getTokenId());
            }

            @Test
            @DisplayName("토큰의 클라이언트 아이디는 인증 코드에 저장된 클라이언트 아이디어야 한다.")
            void shouldClientIdIsSavedClientIdInAuthorizationCode() {
                OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(CLIENT_ID, accessToken.getClient());
            }

            @Test
            @DisplayName("토큰에 저장된 유저 아이디는 인증 코드에 저장된 유저어야 한다.")
            void shouldUserEmailIsSavedUserEmailInAuthorizationCode() {
                OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(STORED_EMAIL, accessToken.getEmail());
            }

            @Test
            @DisplayName("토큰에 저장된 스코프는 인증 코드에 저장된 스코프어야 한다.")
            void shouldScopeIsSavedScopeInAuthorizationCode() {
                OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(STORED_SCOPES, accessToken.getScope());
            }

            @Test
            @DisplayName("토큰의 인증 타입은 AuthorizationCode 타입이어야 한다.")
            void shouldTokenGrantTypeIsAuthorizationCode() {
                OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(AuthorizationGrantType.AUTHORIZATION_CODE, accessToken.getTokenGrantType());
            }

            @Test
            @DisplayName("리플래시 토큰 아이디는 토큰 아이디 생성기에서 생성된 아이디어야 한다.")
            void shouldRefreshTokenIdIsCreatedByTokenIdGenerator() {
                OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(TOKEN_ID, accessToken.getRefreshToken().getTokenId());
            }

            @Nested
            @DisplayName("리플래시 토큰 아이디 생성자가 설정되어 있을시")
            class WhenSetRefreshTokenId {

                @BeforeEach
                void setup() {
                    granter.setRefreshTokenIdGenerator(refreshTokenIdGenerator);

                    when(refreshTokenIdGenerator.generateTokenValue()).thenReturn(REFRESH_TOKEN_ID);
                }

                @Test
                @DisplayName("리플래스 토큰의 아이디는 리플래시 토큰 아이디 생성자가 생성한 아이디어야 한다.")
                void shouldRefreshTokenIdIsCreatedByRefreshTokenIdGenerator() {
                    OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                }

                @AfterEach
                void after() {
                    granter.setRefreshTokenIdGenerator(null);
                }
            }
        }
    }
}