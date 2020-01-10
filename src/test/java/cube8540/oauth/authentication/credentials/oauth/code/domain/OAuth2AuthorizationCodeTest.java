package cube8540.oauth.authentication.credentials.oauth.code.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 인증 코드 도메인 테스트")
class OAuth2AuthorizationCodeTest {

    private static final String RAW_CODE = "CODE";
    private static final AuthorizationCode CODE = new AuthorizationCode(RAW_CODE);

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final String RAW_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final String STATE = "STATE";

    private static final String RAW_REDIRECT_URI = "http://localhost";
    private static final URI REDIRECT_URI = URI.create(RAW_REDIRECT_URI);

    private static final LocalDateTime EXPIRED_DATETIME = LocalDateTime.now().minusNanos(1);
    private static final LocalDateTime NOT_EXPIRED_DATETIME = LocalDateTime.now().plusMinutes(1);

    private static final Set<OAuth2ScopeId> SCOPES = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("SCOPE-1"),
            new OAuth2ScopeId("SCOPE-2"),
            new OAuth2ScopeId("SCOPE-3")));

    private AuthorizationCodeGenerator codeGenerator;

    @BeforeEach
    void setup() {
        this.codeGenerator = mock(AuthorizationCodeGenerator.class);
    }

    @Nested
    @DisplayName("요청 정보 저장")
    class SaveAuthorizationRequest {
        private OAuth2AuthorizationCode code;
        private AuthorizationRequest request;

        @BeforeEach
        void setup() {
            this.request = mock(AuthorizationRequest.class);

            when(request.clientId()).thenReturn(CLIENT_ID);
            when(request.email()).thenReturn(EMAIL);
            when(request.state()).thenReturn(STATE);
            when(request.redirectURI()).thenReturn(REDIRECT_URI);
            when(request.approvedScopes()).thenReturn(SCOPES);
            when(codeGenerator.generate()).thenReturn(CODE);

            this.code = new OAuth2AuthorizationCode(codeGenerator, NOT_EXPIRED_DATETIME);
        }

        @Test
        @DisplayName("인자로 받은 클라이언트 아이디를 저장해야 한다.")
        void shouldSaveGivenClientId() {
            this.code.setAuthorizationRequest(request);

            assertEquals(CLIENT_ID, this.code.getClientId());
        }

        @Test
        @DisplayName("인자로 받은 유저 이메일을 저장해야 한다.")
        void shouldSaveGivenUserEmail() {
            this.code.setAuthorizationRequest(request);

            assertEquals(EMAIL, this.code.getEmail());
        }

        @Test
        @DisplayName("인자로 받은 STATE 속성을 저장해야 한다.")
        void shouldSaveGivenStateProperty() {
            this.code.setAuthorizationRequest(request);

            assertEquals(STATE, this.code.getState());
        }

        @Test
        @DisplayName("인자로 받은 리다이렉트 주소를 저장해야 한다.")
        void shouldSaveGivenRedirectUri() {
            this.code.setAuthorizationRequest(request);

            assertEquals(REDIRECT_URI, this.code.getRedirectURI());
        }

        @Test
        @DisplayName("인자로 받은 스코프를 저장해야 한다.")
        void shouldSaveGivenScopes() {
            this.code.setAuthorizationRequest(request);

            assertEquals(SCOPES, this.code.getApprovedScopes());
        }
    }

    @Nested
    @DisplayName("인증 코드 유효성 검사")
    class AuthorizationCodeValidate {
        private AuthorizationRequest savedRequest;

        @BeforeEach
        void setup() {
            this.savedRequest = mock(AuthorizationRequest.class);

            when(savedRequest.clientId()).thenReturn(CLIENT_ID);
            when(savedRequest.email()).thenReturn(EMAIL);
            when(savedRequest.state()).thenReturn(STATE);
            when(savedRequest.redirectURI()).thenReturn(REDIRECT_URI);
            when(savedRequest.approvedScopes()).thenReturn(SCOPES);
            when(codeGenerator.generate()).thenReturn(CODE);
        }

        @Nested
        @DisplayName("현재시간이 코드의 만료일을 넘었을시")
        class WhenNowGraterThenExpirationDateTime {
            private OAuth2AuthorizationCode code;

            @BeforeEach
            void setup() {
                this.code = new OAuth2AuthorizationCode(codeGenerator, EXPIRED_DATETIME);
            }

            @Test
            @DisplayName("AuthorizationCodeExpiredException이 발생해야 한다.")
            void shouldThrowsAuthorizationCodeExpiredException() {
                assertThrows(AuthorizationCodeExpiredException.class, () -> code.validateWithAuthorizationRequest(savedRequest));
            }
        }

        @Nested
        @DisplayName("리다이렉트 주소가 일치하지 않을시")
        class WhenRedirectUriMismatch {
            private AuthorizationRequest request;
            private OAuth2AuthorizationCode code;

            @BeforeEach
            void setup() {
                this.request = mock(AuthorizationRequest.class);
                this.code = new OAuth2AuthorizationCode(codeGenerator, NOT_EXPIRED_DATETIME);

                this.code.setAuthorizationRequest(savedRequest);
                when(request.redirectURI()).thenReturn(URI.create("http://mismach-uri.info"));
            }

            @Test
            @DisplayName("RedirectMismatchException이 발생해야 한다.")
            void shouldThrowsRedirectMismatchException() {
                assertThrows(RedirectMismatchException.class, () -> code.validateWithAuthorizationRequest(request));
            }
        }

        @Nested
        @DisplayName("클라이언트 아이디가 다를시")
        class WhenClientIdMismatch {
            private AuthorizationRequest request;
            private OAuth2AuthorizationCode code;

            @BeforeEach
            void setup() {
                this.request = mock(AuthorizationRequest.class);
                this.code = new OAuth2AuthorizationCode(codeGenerator, NOT_EXPIRED_DATETIME);

                this.code.setAuthorizationRequest(savedRequest);
                when(request.redirectURI()).thenReturn(REDIRECT_URI);
                when(request.clientId()).thenReturn(new OAuth2ClientId("MISMATCH-CLIENT-ID"));
            }

            @Test
            @DisplayName("InvalidClientException이 발생해야 한다.")
            void shouldThrowsInvalidClientException() {
                assertThrows(InvalidClientException.class, () -> this.code.validateWithAuthorizationRequest(request));
            }
        }

        @Nested
        @DisplayName("일치하지 않는 정보가 없을시")
        class WhenNotMismatchRequest {
            private AuthorizationRequest request;
            private OAuth2AuthorizationCode code;

            @BeforeEach
            void setup() {
                this.request = mock(AuthorizationRequest.class);
                this.code = new OAuth2AuthorizationCode(codeGenerator, NOT_EXPIRED_DATETIME);

                this.code.setAuthorizationRequest(savedRequest);
                when(request.redirectURI()).thenReturn(REDIRECT_URI);
                when(request.clientId()).thenReturn(CLIENT_ID);
            }

            @Test
            @DisplayName("어떠한 에러도 발생시키지 않아야 한다.")
            void shouldNotThrows() {
                assertDoesNotThrow(() -> this.code.validateWithAuthorizationRequest(request));
            }
        }
    }
}