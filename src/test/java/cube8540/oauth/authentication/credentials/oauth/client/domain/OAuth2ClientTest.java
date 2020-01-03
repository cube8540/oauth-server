package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OAuth2 클라이언트 테스트")
class OAuth2ClientTest {

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);
    private static final String SECRET = "SECRET";
    private static final String CLIENT_NAME = "CLIENT_NAME";

    @Nested
    @DisplayName("OAuth2 클라이언트 생성")
    class InitializeOAuth2Client {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = new OAuth2Client(RAW_CLIENT_ID, SECRET, CLIENT_NAME);
        }

        @Test
        @DisplayName("인자로 받은 클라이언트 아이디를 저장해야 한다.")
        void shouldSaveGivenClientId() {
            assertEquals(CLIENT_ID, client.getClientId());
        }

        @Test
        @DisplayName("인자로 받은 클라이언트 패스워드를 저장해야 한다.")
        void shouldSaveGivenSecret() {
            assertEquals(SECRET, client.getSecret());
        }

        @Test
        @DisplayName("인자로 받은 클라이언트명을 저장해야 한다.")
        void shouldSaveGivenClientName() {
            assertEquals(CLIENT_NAME, client.getClientName());
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
            this.client = new OAuth2Client(RAW_CLIENT_ID, SECRET, CLIENT_NAME);
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
            this.client = new OAuth2Client(RAW_CLIENT_ID, SECRET, CLIENT_NAME);
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
            this.client = new OAuth2Client(RAW_CLIENT_ID, SECRET, CLIENT_NAME);
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
            this.client = new OAuth2Client(RAW_CLIENT_ID, SECRET, CLIENT_NAME);
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
            this.client = new OAuth2Client(RAW_CLIENT_ID, SECRET, CLIENT_NAME);
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
            this.client = new OAuth2Client(RAW_CLIENT_ID, SECRET, CLIENT_NAME);
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
}