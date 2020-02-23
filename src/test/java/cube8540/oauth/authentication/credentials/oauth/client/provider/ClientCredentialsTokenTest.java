package cube8540.oauth.authentication.credentials.oauth.client.provider;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 인증 토큰 테스트")
class ClientCredentialsTokenTest {

    private static final String CLIENT_ID = "CLIENT_ID";
    private static final String CLIENT_SECRET = "CLIENT_SECRET";

    private static final Collection<? extends GrantedAuthority> AUTHORITIES = Collections.emptyList();

    @Nested
    @DisplayName("토큰 생성")
    class InitializeToken {

        @Nested
        @DisplayName("권한 정보 없이 토큰을 생성")
        class WhenWithoutAuthority {
            private ClientCredentialsToken token;

            @BeforeEach
            void setup() {
                this.token = new ClientCredentialsToken(CLIENT_ID, CLIENT_SECRET);
            }

            @Test
            @DisplayName("생성자로 받은 클라이언트 아이디를 저장해야 한다.")
            void shouldSaveGivenClientId() {
                assertEquals(CLIENT_ID, token.getPrincipal());
            }

            @Test
            @DisplayName("생성자로 받은 클라이언트 패스워드를 저장해야 한다.")
            void shouldSaveGiveSecret() {
                assertEquals(CLIENT_SECRET, token.getCredentials());
            }

            @Test
            @DisplayName("권한 정보는 빈 배열이어야 한다.")
            void shouldAuthoritiesEmpty() {
               assertEquals(Collections.emptyList(), token.getAuthorities());
            }

            @Test
            @DisplayName("인증 여부는 false가 반환되어야 한다.")
            void shouldIsAuthenticatedReturnsFalse() {
                assertFalse(token.isAuthenticated());
            }
        }

        @Nested
        @DisplayName("권한 정보와 토큰을 생성")
        class WhenWithAuthority {
            private ClientCredentialsToken token;

            @BeforeEach
            void setup() {
                this.token = new ClientCredentialsToken(CLIENT_ID, CLIENT_SECRET, AUTHORITIES);
            }

            @Test
            @DisplayName("생성자로 받은 클라이언트 아이디를 저장해야 한다.")
            void shouldSaveGivenClientId() {
                assertEquals(CLIENT_ID, token.getPrincipal());
            }

            @Test
            @DisplayName("생성자로 받은 클라이언트 패스워드를 저장해야 한다.")
            void shouldSaveGiveSecret() {
                assertEquals(CLIENT_SECRET, token.getCredentials());
            }

            @Test
            @DisplayName("생성자로 받은 권한 정보를 저장해야 한다.")
            void shouldSaveGivenAuthorities() {
                assertEquals(AUTHORITIES, token.getAuthorities());
            }

            @Test
            @DisplayName("인증 여부는 true가 반환되어야 한다.")
            void shouldIsAuthenticatedReturnsTrue() {
                assertTrue(token.isAuthenticated());
            }
        }
    }

    @Nested
    @DisplayName("토큰에 권한 설정")
    class SetAuthorities {

        private ClientCredentialsToken token;

        @BeforeEach
        void setup() {
            this.token = new ClientCredentialsToken(CLIENT_ID, CLIENT_SECRET);
        }

        @Test
        @DisplayName("IllegalArgumentException이 발생해야 한다.")
        void shouldThrowsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> token.setAuthenticated(true));
            assertFalse(token.isAuthenticated());
        }
    }

    @Nested
    @DisplayName("민감한 정보 삭제")
    class EraseCredentials {
        private ClientCredentialsToken token0;
        private CredentialsContainer principal;
        private CredentialsContainer credentials;
        private CredentialsContainer details0;

        private ClientCredentialsToken token1;
        private Object details1 = new Object();

        @BeforeEach
        void setup() {
            this.principal = mock(CredentialsContainer.class);
            this.credentials = mock(CredentialsContainer.class);
            this.details0 = mock(CredentialsContainer.class);

            this.token0 = new ClientCredentialsToken(principal, credentials, AUTHORITIES);
            this.token1 = new ClientCredentialsToken(CLIENT_ID, CLIENT_SECRET, AUTHORITIES);

            this.token0.setDetails(details0);
            this.token1.setDetails(details1);
        }

        @Test
        @DisplayName("credentials 속성은 null로 저장되어야 한다.")
        void shouldSetNullCredentials() {
            this.token0.eraseCredentials();
            this.token1.eraseCredentials();

            assertNull(token0.getCredentials());
            assertNull(token1.getCredentials());
        }

        @Test
        @DisplayName("CredentialsContainer를 구현한 속성들은 반드시 삭제되어야 한다.")
        void shouldEraseCredentialsContainerProperty() {
            this.token0.eraseCredentials();
            this.token1.eraseCredentials();

            verify(principal, times(1)).eraseCredentials();
            verify(credentials, times(1)).eraseCredentials();
            verify(details0, times(1)).eraseCredentials();
            assertNull(token1.getCredentials());
            assertNotNull(token1.getPrincipal());
            assertNotNull(token1.getDetails());
        }
    }

    @Nested
    @DisplayName("인증 정보 이름 반환")
    class GetPrincipalName {

        @Nested
        @DisplayName("인증 정보가 String일시")
        class WhenPrincipalNameString {

            private ClientCredentialsToken token;

            @BeforeEach
            void setup() {
                this.token = new ClientCredentialsToken(CLIENT_ID, CLIENT_SECRET);
            }

            @Test
            @DisplayName("저장된 인증 정보의 이름을 반환한다.")
            void shouldReturnsPrincipalName() {
                assertEquals(CLIENT_ID, token.getName());
            }
        }

        @Nested
        @DisplayName("인증 정보가 ClientDetails 일시")
        class WhenPrincipalNameClientDetails {
            private ClientCredentialsToken token;
            private OAuth2ClientDetails clientDetails;

            @BeforeEach
            void setup() {
                this.clientDetails = mock(OAuth2ClientDetails.class);
                this.token = new ClientCredentialsToken(clientDetails, CLIENT_SECRET);
                when(clientDetails.getClientId()).thenReturn(CLIENT_ID);
            }

            @Test
            @DisplayName("OAuth2ClientDetails에 저장된 클라이언트 아이디를 반환해야 한다.")
            void shouldReturnsOAuth2ClientDetailsClientId() {
                assertEquals(CLIENT_ID, token.getName());
            }
        }
    }
}