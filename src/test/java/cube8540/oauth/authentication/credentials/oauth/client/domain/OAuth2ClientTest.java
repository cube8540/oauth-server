package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 클라이언트 테스트")
class OAuth2ClientTest {

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final String RAW_SECRET = "SECRET";
    private static final String RAW_ENCODING_SECRET = "ENCODING-SECRET";

    private static final String CLIENT_NAME = "CLIENT_NAME";

    private static final UserEmail CLIENT_OWNER = new UserEmail("email@email.com");

    @Nested
    @DisplayName("OAuth2 클라이언트 생성")
    class InitializeOAuth2Client {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(RAW_CLIENT_ID, RAW_SECRET, CLIENT_NAME, CLIENT_OWNER);
        }

        @Test
        @DisplayName("인자로 받은 클라이언트 아이디를 저장해야 한다.")
        void shouldSaveGivenClientId() {
            assertEquals(CLIENT_ID, client.getClientId());
        }

        @Test
        @DisplayName("인자로 받은 클라이언트 패스워드를 저장해야 한다.")
        void shouldSaveGivenSecret() {
            assertEquals(RAW_SECRET, client.getSecret());
        }

        @Test
        @DisplayName("인자로 받은 클라이언트명을 저장해야 한다.")
        void shouldSaveGivenClientName() {
            assertEquals(CLIENT_NAME, client.getClientName());
        }

        @Test
        @DisplayName("인자로 받은 클라이언트 소우자를 저장해야 한다.")
        void shouldSaveGivenClientOwner() {
            assertEquals(CLIENT_OWNER, client.getOwner());
        }

        @Test
        @DisplayName("인증 토큰의 만료 시간을 기본 시간으로 저장해야 한다.")
        void shouldSaveDefaultAccessTokenValidity() {
            assertEquals(OAuth2Client.DEFAULT_ACCESS_TOKEN_VALIDITY, client.getAccessTokenValidity());
        }

        @Test
        @DisplayName("리플래시 토큰의 만료 시간을 기본 시간으로 저장해야 한다.")
        void shouldSaveDefaultRefreshTokenValidity() {
            assertEquals(OAuth2Client.DEFAULT_REFRESH_TOKEN_VALIDITY, client.getRefreshTokenValidity());
        }
    }

    @Nested
    @DisplayName("리다이렉트 URI 저장")
    class AddRedirectURI {
        private URI newRedirectURI = URI.create("http://localhost");
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(RAW_CLIENT_ID, RAW_SECRET, CLIENT_NAME, CLIENT_OWNER);
        }

        @Nested
        @DisplayName("새 리다이렉트 URI를 저장할시")
        class WhenNewRedirectURI {
            private URI newDifferentRedirectURI = URI.create("http://localhost:81");

            @Test
            @DisplayName("인자로 받은 URI를 저장해야함")
            void shouldSaveGiveURI() {
                client.addRedirectURI(newRedirectURI);
                client.addRedirectURI(newDifferentRedirectURI);

                assertTrue(client.getRedirectURI().contains(newRedirectURI));
                assertTrue(client.getRedirectURI().contains(newDifferentRedirectURI));
            }
        }

        @Nested
        @DisplayName("이미 저장된 리다이렉트 URI를 다시 저장할시")
        class WhenGivenAlreadyRedirectURI {

            @BeforeEach
            void setup() {
                client.addRedirectURI(newRedirectURI);
            }

            @Test
            @DisplayName("인자로 받은 URI가 저장되어 있어야 한다.")
            void shouldStoredGiveRedirectURI() {
                client.addRedirectURI(newRedirectURI);
                assertTrue(client.getRedirectURI().contains(newRedirectURI));
            }

            @Test
            @DisplayName("같은 URI는 하나만 저장되어 있어야 한다.")
            void shouldStoredOnlyOneSameURI() {
                client.addRedirectURI(newRedirectURI);

                long size = client.getRedirectURI().stream().filter(uri -> uri.equals(newRedirectURI)).count();
                assertEquals(1, size);
            }
        }
    }

    @Nested
    @DisplayName("리다이렉트 URI 삭제")
    class RemoveRedirectURI {
        private URI redirectURI = URI.create("http://localhost");
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(RAW_CLIENT_ID, RAW_SECRET, CLIENT_NAME, CLIENT_OWNER);
        }

        @Nested
        @DisplayName("삭제하려는 리다이렉트 URI가 저장되어 있지 않을시")
        class WhenRemoveNotStoredURI {

            @Test
            @DisplayName("해당 요청은 무시한다.")
            void shouldNothing() {
                assertDoesNotThrow(() -> client.removeRedirectURI(redirectURI));
            }
        }

        @Nested
        @DisplayName("삭제하려는 리다이렉트 URI가 저장되어 있을시")
        class WhenRemoveStoredURI {

            @BeforeEach
            void setup() {
                client.addRedirectURI(redirectURI);
            }

            @Test
            @DisplayName("인자로 받은 URI를 삭제한다.")
            void shouldRemoveGivenRedirectURI() {
                client.removeRedirectURI(redirectURI);
                assertFalse(client.getRedirectURI().contains(redirectURI));
            }
        }
    }

    @Nested
    @DisplayName("클라이언트 인증 방식 저장")
    class AddClientGrantType {
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(RAW_CLIENT_ID, RAW_SECRET, CLIENT_NAME, CLIENT_OWNER);
        }

        @Nested
        @DisplayName("새 클라이언즈 인증 방식을 저장할시")
        class WhenNewGrantType {

            @Test
            @DisplayName("인자로 받은 클라이언트 인증 방식을 저장해야함")
            void shouldSaveGiveGrantType() {
                client.addGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                client.addGrantType(AuthorizationGrantType.PASSWORD);

                assertTrue(client.getGrantType().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
                assertTrue(client.getGrantType().contains(AuthorizationGrantType.PASSWORD));
            }
        }

        @Nested
        @DisplayName("이미 저장된 리다이렉트 URI를 다시 저장할시")
        class WhenGivenAlreadyGrantType {

            @BeforeEach
            void setup() {
                client.addGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
            }

            @Test
            @DisplayName("인자로 받은 인증 방식이 저장되어 있어야 한다.")
            void shouldStoredGiveGrantType() {
                client.addGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                assertTrue(client.getGrantType().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
            }

            @Test
            @DisplayName("같은 인증 방식은 하나만 저장되어 있어야 한다.")
            void shouldStoredOnlyOneSameGrantType() {
                client.addGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);

                long size = client.getGrantType().stream()
                        .filter(grantType -> grantType.equals(AuthorizationGrantType.AUTHORIZATION_CODE)).count();
                assertEquals(1, size);
            }
        }
    }

    @Nested
    @DisplayName("인증 방식 삭제")
    class RemoveGrantType {
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(RAW_CLIENT_ID, RAW_SECRET, CLIENT_NAME, CLIENT_OWNER);
        }

        @Nested
        @DisplayName("삭제하려는 인증 방식이 저장되어 있지 않을시")
        class WhenRemoveNotStoredGrantType {

            @Test
            @DisplayName("해당 요청은 무시한다.")
            void shouldNothing() {
                assertDoesNotThrow(() -> client.removeGrantType(AuthorizationGrantType.AUTHORIZATION_CODE));
            }
        }

        @Nested
        @DisplayName("삭제하려는 인증 방식이 저장되어 있을시")
        class WhenRemoveStoredGrantType {

            @BeforeEach
            void setup() {
                client.addGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
            }

            @Test
            @DisplayName("인자로 받은 인증 방식을 삭제한다.")
            void shouldRemoveGivenGrantType() {
                client.removeGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                assertFalse(client.getGrantType().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
            }
        }
    }

    @Nested
    @DisplayName("스코프 저장")
    class AddScope {
        private OAuth2ScopeId newScope;
        private OAuth2Client client;

        @BeforeEach
        void setup(){
            this.newScope = new OAuth2ScopeId("SCOPE-1");
            this.client = new OAuth2Client(RAW_CLIENT_ID, RAW_SECRET, CLIENT_NAME, CLIENT_OWNER);
        }

        @Nested
        @DisplayName("새 스코프를 저장할시")
        class WhenNewScope {
            private OAuth2ScopeId newDifferentScope;

            @BeforeEach
            void setup() {
                this.newDifferentScope = new OAuth2ScopeId("SCOPE-2");
            }

            @Test
            @DisplayName("인자로 받은 스코프를 저장해야함")
            void shouldSaveGiveScope() {
                client.addScope(newScope);
                client.addScope(newDifferentScope);

                assertTrue(client.getScope().contains(newScope));
                assertTrue(client.getScope().contains(newDifferentScope));
            }
        }

        @Nested
        @DisplayName("이미 저장된 스코프를 다시 저장할시")
        class WhenGivenAlreadyScope {

            @BeforeEach
            void setup() {
                client.addScope(newScope);
            }

            @Test
            @DisplayName("인자로 받은 스코프가 저장되어 있어야 한다.")
            void shouldStoredGiveScope() {
                client.addScope(newScope);
                assertTrue(client.getScope().contains(newScope));
            }

            @Test
            @DisplayName("같은 스코프는 하나만 저장되어 있어야 한다.")
            void shouldStoredOnlyOneSameScope() {
                client.addScope(newScope);

                long size = client.getScope().stream()
                        .filter(scope -> scope.equals(newScope)).count();
                assertEquals(1, size);
            }
        }
    }

    @Nested
    @DisplayName("스코프 삭제")
    class RemoveScope {
        private OAuth2ScopeId scope;
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.scope = new OAuth2ScopeId("SCOPE-1");
            this.client = new OAuth2Client(RAW_CLIENT_ID, RAW_SECRET, CLIENT_NAME, CLIENT_OWNER);
        }

        @Nested
        @DisplayName("삭제하려는 스코프가 저장되어 있지 않을시")
        class WhenRemoveNotStoredScope {

            @Test
            @DisplayName("해당 요청은 무시한다.")
            void shouldNothing() {
                assertDoesNotThrow(() -> client.removeScope(scope));
            }
        }

        @Nested
        @DisplayName("삭제하려는 스코프가 저장되어 있을시")
        class WhenRemoveStoredScope {

            @BeforeEach
            void setup() {
                client.addScope(scope);
            }

            @Test
            @DisplayName("인자로 받은 인증 방식을 삭제한다.")
            void shouldRemoveGivenGrantType() {
                client.removeScope(scope);
                assertFalse(client.getScope().contains(scope));
            }
        }
    }

    @Nested
    @DisplayName("클라이언트 패스워드 암호화")
    class SecretEncrypting {
        private OAuth2Client client;
        private PasswordEncoder passwordEncoder;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(RAW_CLIENT_ID, RAW_SECRET, CLIENT_NAME, CLIENT_OWNER);
            this.passwordEncoder = mock(PasswordEncoder.class);

            when(passwordEncoder.encode(RAW_SECRET)).thenReturn(RAW_ENCODING_SECRET);
        }

        @Test
        @DisplayName("클라이언트 패스워드를 암호화 하여 저장해야 한다.")
        void shouldSaveEncryptedClientSecret() {
            client.encrypted(passwordEncoder);

            assertEquals(RAW_ENCODING_SECRET, client.getSecret());
        }
    }

    @Nested
    @DisplayName("클라이언트 유효성 채크")
    class ClientValidation {
        private OAuth2Client client;

        private OAuth2ClientValidatePolicy policy;

        private ValidationRule<OAuth2Client> clientIdRule;
        private ValidationRule<OAuth2Client> secretRule;
        private ValidationRule<OAuth2Client> clientNameRule;
        private ValidationRule<OAuth2Client> grantTypeRule;
        private ValidationRule<OAuth2Client> scopeRule;
        private ValidationRule<OAuth2Client> ownerRule;

        @BeforeEach
        @SuppressWarnings("unchecked")
        void setup() {
            this.client = new OAuth2Client(RAW_CLIENT_ID, RAW_SECRET, CLIENT_NAME, CLIENT_OWNER);

            this.policy = mock(OAuth2ClientValidatePolicy.class);
            this.clientIdRule = mock(ValidationRule.class);
            this.secretRule = mock(ValidationRule.class);
            this.clientNameRule = mock(ValidationRule.class);
            this.grantTypeRule = mock(ValidationRule.class);
            this.scopeRule = mock(ValidationRule.class);
            this.ownerRule = mock(ValidationRule.class);

            when(policy.clientIdRule()).thenReturn(clientIdRule);
            when(policy.secretRule()).thenReturn(secretRule);
            when(policy.clientNameRule()).thenReturn(clientNameRule);
            when(policy.grantTypeRule()).thenReturn(grantTypeRule);
            when(policy.scopeRule()).thenReturn(scopeRule);
            when(policy.ownerRule()).thenReturn(ownerRule);
        }

        @Nested
        @DisplayName("클라이언트 아이디가 유효하지 않을시")
        class WhenClientIdIsNotAllowed {
            private ValidationError clientIdError;

            @BeforeEach
            void setup() {
                this.clientIdError = new ValidationError("clientId", "invalid client id");

                when(clientIdRule.isValid(client)).thenReturn(false);
                when(secretRule.isValid(client)).thenReturn(true);
                when(clientNameRule.isValid(client)).thenReturn(true);
                when(grantTypeRule.isValid(client)).thenReturn(true);
                when(scopeRule.isValid(client)).thenReturn(true);
                when(ownerRule.isValid(client)).thenReturn(true);
                when(clientIdRule.error()).thenReturn(clientIdError);
            }

            @Test
            @DisplayName("ClientInvalidException이 발생해야 한다.")
            void shouldThrowsClientInvalidException() {
                assertThrows(ClientInvalidException.class, () -> client.validate(policy));
            }

            @Test
            @DisplayName("클라이언트 아이디 유효성에 관련된 에러가 포함되어야 한다.")
            void shouldContainsClientIdErrorMessage() {
                ClientInvalidException exception = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
                assertTrue(exception.getErrors().contains(clientIdError));
            }
        }

        @Nested
        @DisplayName("클라이언트 패스워드가 유효하지 않을시")
        class WhenClientSecretIsNotAllowed {
            private ValidationError passwordError;

            @BeforeEach
            void setup() {
                this.passwordError = new ValidationError("secret", "invalid secret");

                when(clientIdRule.isValid(client)).thenReturn(true);
                when(secretRule.isValid(client)).thenReturn(false);
                when(clientNameRule.isValid(client)).thenReturn(true);
                when(grantTypeRule.isValid(client)).thenReturn(true);
                when(scopeRule.isValid(client)).thenReturn(true);
                when(ownerRule.isValid(client)).thenReturn(true);
                when(secretRule.error()).thenReturn(passwordError);
            }

            @Test
            @DisplayName("ClientInvalidException이 발생해야 한다.")
            void shouldThrowsClientInvalidException() {
                assertThrows(ClientInvalidException.class, () -> client.validate(policy));
            }

            @Test
            @DisplayName("클라이언트 패스워드 유효성에 관련된 에러가 포함되어야 한다.")
            void shouldContainsSecretErrorMessage() {
                ClientInvalidException exception = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
                assertTrue(exception.getErrors().contains(passwordError));
            }
        }

        @Nested
        @DisplayName("클라이언트명이 유효하지 않을시")
        class WhenClientNameIsNotAllowed {
            private ValidationError nameError;

            @BeforeEach
            void setup() {
                this.nameError = new ValidationError("clientName", "invalid client name");

                when(clientIdRule.isValid(client)).thenReturn(true);
                when(secretRule.isValid(client)).thenReturn(true);
                when(clientNameRule.isValid(client)).thenReturn(false);
                when(grantTypeRule.isValid(client)).thenReturn(true);
                when(scopeRule.isValid(client)).thenReturn(true);
                when(ownerRule.isValid(client)).thenReturn(true);
                when(clientNameRule.error()).thenReturn(nameError);
            }

            @Test
            @DisplayName("ClientInvalidException이 발생해야 한다.")
            void shouldThrowsClientInvalidException() {
                assertThrows(ClientInvalidException.class, () -> client.validate(policy));
            }

            @Test
            @DisplayName("클라이언트명 유효성에 관련된 에러가 포함되어야 한다.")
            void shouldContainsNameErrorMessage() {
                ClientInvalidException exception = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
                assertTrue(exception.getErrors().contains(nameError));
            }
        }

        @Nested
        @DisplayName("클라이언트 인가 방식이 유효하지 않을시")
        class WhenClientAuthorizationGrantTypeIsNotAllowed {
            private ValidationError grantError;

            @BeforeEach
            void setup() {
                this.grantError = new ValidationError("grantType", "invalid grant type");

                when(clientIdRule.isValid(client)).thenReturn(true);
                when(secretRule.isValid(client)).thenReturn(true);
                when(clientNameRule.isValid(client)).thenReturn(true);
                when(grantTypeRule.isValid(client)).thenReturn(false);
                when(scopeRule.isValid(client)).thenReturn(true);
                when(ownerRule.isValid(client)).thenReturn(true);
                when(grantTypeRule.error()).thenReturn(grantError);
            }

            @Test
            @DisplayName("ClientInvalidException이 발생해야 한다.")
            void shouldThrowsClientInvalidException() {
                assertThrows(ClientInvalidException.class, () -> client.validate(policy));
            }

            @Test
            @DisplayName("클라이언트 인가 유효성에 관련된 에러가 포함되어야 한다.")
            void shouldContainsClientAuthorizationGrantErrorMessage() {
                ClientInvalidException exception = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
                assertTrue(exception.getErrors().contains(grantError));
            }
        }

        @Nested
        @DisplayName("클라이언트 스코프가 유효하지 않을시")
        class WhenClientScopeIsNotAllowed {
            private ValidationError scopeError;

            @BeforeEach
            void setup() {
                this.scopeError = new ValidationError("scope", "invalid scope");

                when(clientIdRule.isValid(client)).thenReturn(true);
                when(secretRule.isValid(client)).thenReturn(true);
                when(clientNameRule.isValid(client)).thenReturn(true);
                when(grantTypeRule.isValid(client)).thenReturn(true);
                when(scopeRule.isValid(client)).thenReturn(false);
                when(ownerRule.isValid(client)).thenReturn(true);
                when(scopeRule.error()).thenReturn(scopeError);
            }

            @Test
            @DisplayName("ClientInvalidException이 발생해야 한다.")
            void shouldThrowsClientInvalidException() {
                assertThrows(ClientInvalidException.class, () -> client.validate(policy));
            }

            @Test
            @DisplayName("클라이언트 스코프 유효성에 관련된 에러가 포함되어야 한다.")
            void shouldContainsScopeErrorMessage() {
                ClientInvalidException exception = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
                assertTrue(exception.getErrors().contains(scopeError));
            }
        }

        @Nested
        @DisplayName("클라이언트 소유자가 유효하지 않을시")
        class WhenClientOwnerIsNotAllowed {
            private ValidationError ownerError;

            @BeforeEach
            void setup() {
                this.ownerError = new ValidationError("owner", "invalid owner");

                when(clientIdRule.isValid(client)).thenReturn(true);
                when(secretRule.isValid(client)).thenReturn(true);
                when(clientNameRule.isValid(client)).thenReturn(true);
                when(grantTypeRule.isValid(client)).thenReturn(true);
                when(scopeRule.isValid(client)).thenReturn(true);
                when(ownerRule.isValid(client)).thenReturn(false);
                when(ownerRule.error()).thenReturn(ownerError);
            }

            @Test
            @DisplayName("ClientInvalidException이 발생해야 한다.")
            void shouldThrowsClientInvalidException() {
                assertThrows(ClientInvalidException.class, () -> client.validate(policy));
            }

            @Test
            @DisplayName("클라이언트 소유자의 유효성에 관련된 에러가 포함되어야 한다.")
            void shouldContainsScopeErrorMessage() {
                ClientInvalidException exception = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
                assertTrue(exception.getErrors().contains(ownerError));
            }
        }
    }
}