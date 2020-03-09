package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.oauth.authentication.credentials.oauth.client.error.ClientAuthorizationException;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientErrorCodes;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientInvalidException;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OAuth2 클라이언트 테스트")
class OAuth2ClientTest {

    @Nested
    @DisplayName("리다이렉트 URI 저장")
    class AddRedirectURI {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
        }

        @Test
        @DisplayName("인자로 받은 URI 를 저장해야함")
        void shouldSaveGiveURI() {
            client.addRedirectUri(OAuth2ClientTestsHelper.REDIRECT_URI);

            assertTrue(client.getRedirectUris().contains(OAuth2ClientTestsHelper.REDIRECT_URI));
        }
    }

    @Nested
    @DisplayName("리다이렉트 URI 삭제")
    class RemoveRedirectURI {
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);

            this.client.addRedirectUri(OAuth2ClientTestsHelper.REDIRECT_URI);
        }

        @Test
        @DisplayName("인자로 받은 URI 를 삭제한다.")
        void shouldRemoveGivenRedirectURI() {
            client.removeRedirectUri(OAuth2ClientTestsHelper.REDIRECT_URI);

            assertFalse(client.getRedirectUris().contains(OAuth2ClientTestsHelper.REDIRECT_URI));
        }
    }

    @Nested
    @DisplayName("클라이언트 인증 방식 저장")
    class AddClientGrantType {
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
        }

        @Test
        @DisplayName("인자로 받은 클라이언트 인증 방식을 저장해야함")
        void shouldSaveGiveGrantType() {
            client.addGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);

            assertTrue(client.getGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
        }
    }

    @Nested
    @DisplayName("인증 방식 삭제")
    class RemoveGrantType {
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
            this.client.addGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        }

        @Test
        @DisplayName("인자로 받은 인증 방식을 삭제한다.")
        void shouldRemoveGivenGrantType() {
            client.removeGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);

            assertFalse(client.getGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
        }
    }

    @Nested
    @DisplayName("스코프 저장")
    class AddScope {
        private OAuth2Client client;

        @BeforeEach
        void setup(){
            this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
        }

        @Test
        @DisplayName("인자로 받은 스코프를 저장해야함")
        void shouldSaveGiveScope() {
            client.addScope(OAuth2ClientTestsHelper.ADDED_SCOPE);

            assertTrue(client.getScopes().contains(OAuth2ClientTestsHelper.ADDED_SCOPE));
        }
    }

    @Nested
    @DisplayName("스코프 삭제")
    class RemoveScope {
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
            this.client.addScope(OAuth2ClientTestsHelper.ADDED_SCOPE);
        }

        @Test
        @DisplayName("인자로 받은 인증 방식을 삭제한다.")
        void shouldRemoveGivenGrantType() {
            client.removeScope(OAuth2ClientTestsHelper.ADDED_SCOPE);

            assertFalse(client.getScopes().contains(OAuth2ClientTestsHelper.ADDED_SCOPE));
        }
    }

    @Nested
    @DisplayName("클라이언트 패스워드 암호화")
    class SecretEncrypting {
        private PasswordEncoder encoder;

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
            this.encoder = OAuth2ClientTestsHelper.mockPasswordEncoder().encode().build();
        }

        @Test
        @DisplayName("클라이언트 패스워드를 암호화 하여 저장해야 한다.")
        void shouldSaveEncryptedClientSecret() {
            client.encrypted(encoder);

            Assertions.assertEquals(OAuth2ClientTestsHelper.RAW_ENCODING_SECRET, client.getSecret());
        }
    }

    @Nested
    @DisplayName("클라이언트 유효성 채크")
    class ClientValidation {

        @Nested
        @DisplayName("클라이언트 아이디가 유효하지 않을시")
        class WhenClientIdIsNotAllowed {
            private ValidationError clientIdError;
            private OAuth2ClientValidatePolicy policy;

            private OAuth2Client client;

            @BeforeEach
            void setup() {
                this.clientIdError = new ValidationError("clientId", "invalid client id");
                this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
                ValidationRule<OAuth2Client> clientIdRule = OAuth2ClientTestsHelper.mocKValidationRule().configValidationFalse(client).error(clientIdError).build();
                this.policy = OAuth2ClientTestsHelper.mockValidationPolicy().clientIdRule(clientIdRule)
                        .secretRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .clientNameRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .grantTypeRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .scopeRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .ownerRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .build();
            }

            @Test
            @DisplayName("ClientInvalidException 이 발생해야 해야 한다.")
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
            private OAuth2ClientValidatePolicy policy;

            private OAuth2Client client;

            @BeforeEach
            void setup() {
                this.passwordError = new ValidationError("secret", "invalid secret");
                this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
                ValidationRule<OAuth2Client> secretRule = OAuth2ClientTestsHelper.mocKValidationRule().configValidationFalse(client).error(passwordError).build();
                this.policy = OAuth2ClientTestsHelper.mockValidationPolicy().clientIdRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .secretRule(secretRule)
                        .clientNameRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .grantTypeRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .scopeRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .ownerRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .build();
            }

            @Test
            @DisplayName("ClientInvalidException 이 발생해야 한다.")
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
            private OAuth2ClientValidatePolicy policy;

            private OAuth2Client client;

            @BeforeEach
            void setup() {
                this.nameError = new ValidationError("clientName", "invalid client name");
                this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
                ValidationRule<OAuth2Client> clientNameRule = OAuth2ClientTestsHelper.mocKValidationRule().configValidationFalse(client).error(nameError).build();
                this.policy = OAuth2ClientTestsHelper.mockValidationPolicy().clientIdRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .secretRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .clientNameRule(clientNameRule)
                        .grantTypeRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .scopeRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .ownerRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .build();
            }

            @Test
            @DisplayName("ClientInvalidException 이 발생해야 한다.")
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
            private OAuth2ClientValidatePolicy policy;

            private OAuth2Client client;

            @BeforeEach
            void setup() {
                this.grantError = new ValidationError("grantType", "invalid grant type");
                this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
                ValidationRule<OAuth2Client> grantRule = OAuth2ClientTestsHelper.mocKValidationRule().configValidationFalse(client).error(grantError).build();
                this.policy = OAuth2ClientTestsHelper.mockValidationPolicy().clientIdRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .secretRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .clientNameRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .grantTypeRule(grantRule)
                        .scopeRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .ownerRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .build();
            }

            @Test
            @DisplayName("ClientInvalidException 이 발생해야 한다.")
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
            private OAuth2ClientValidatePolicy policy;

            private OAuth2Client client;

            @BeforeEach
            void setup() {
                this.scopeError = new ValidationError("scope", "invalid scope");
                this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
                ValidationRule<OAuth2Client> scopeRule = OAuth2ClientTestsHelper.mocKValidationRule().configValidationFalse(client).error(scopeError).build();
                this.policy = OAuth2ClientTestsHelper.mockValidationPolicy().clientIdRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .secretRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .clientNameRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .grantTypeRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .scopeRule(scopeRule)
                        .ownerRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .build();
            }

            @Test
            @DisplayName("ClientInvalidException 이 발생해야 한다.")
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
            private OAuth2ClientValidatePolicy policy;

            private OAuth2Client client;

            @BeforeEach
            void setup() {
                this.ownerError = new ValidationError("owner", "invalid owner");
                this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
                ValidationRule<OAuth2Client> ownerRule = OAuth2ClientTestsHelper.mocKValidationRule().configValidationFalse(client).error(ownerError).build();
                this.policy = OAuth2ClientTestsHelper.mockValidationPolicy().clientIdRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .secretRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .clientNameRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .grantTypeRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .scopeRule(OAuth2ClientTestsHelper.mocKValidationRule().configValidationTrue(client).build())
                        .ownerRule(ownerRule)
                        .build();
            }

            @Test
            @DisplayName("ClientInvalidException 이 발생해야 한다.")
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

    @Nested
    @DisplayName("클라이언트 패스워드 변경")
    class ClientChangeSecret {

        @Nested
        @DisplayName("이전에 사용하던 패스워드가 서로 일치 하지 않을시")
        class WhenExistsPasswordIsNotMatched {
            private PasswordEncoder passwordEncoder;

            private OAuth2Client client;

            @BeforeEach
            void setup() {
                this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
                this.passwordEncoder = OAuth2ClientTestsHelper.mockPasswordEncoder().mismatches().build();
            }

            @Test
            @DisplayName("ClientAuthorizationException 이 발생해야 해야 하며 에러 코드는 INVALID_PASSWORD 이어야 한다.")
            void shouldThrowsClientAuthorizationException() {
                ClientAuthorizationException e = assertThrows(ClientAuthorizationException.class, () -> client.changeSecret(OAuth2ClientTestsHelper.RAW_SECRET, OAuth2ClientTestsHelper.RAW_CHANGE_SECRET, passwordEncoder));
                Assertions.assertEquals(ClientErrorCodes.INVALID_PASSWORD, e.getCode());
            }
        }

        @Nested
        @DisplayName("이전에 사용하던 패스워드가 서로 일치할시")
        class WhenExistsPasswordMatched {
            private PasswordEncoder encoder;

            private OAuth2Client client;

            @BeforeEach
            void setup() {
                this.client = new OAuth2Client(OAuth2ClientTestsHelper.RAW_CLIENT_ID, OAuth2ClientTestsHelper.RAW_SECRET);
                this.encoder = OAuth2ClientTestsHelper.mockPasswordEncoder().encode().matches().build();

                this.client.encrypted(encoder);
            }

            @Test
            @DisplayName("요청 받은 패스워드로 클라이언트의 패스워드를 변경해야 한다.")
            void shouldChangeSecretWithRequestingSecret() {
                client.changeSecret(OAuth2ClientTestsHelper.RAW_SECRET, OAuth2ClientTestsHelper.RAW_CHANGE_SECRET, encoder);

                Assertions.assertEquals(OAuth2ClientTestsHelper.RAW_CHANGE_SECRET, client.getSecret());
            }
        }
    }
}