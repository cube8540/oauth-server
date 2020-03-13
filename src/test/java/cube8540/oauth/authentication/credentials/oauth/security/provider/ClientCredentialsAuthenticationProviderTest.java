package cube8540.oauth.authentication.credentials.oauth.security.provider;

import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

import static cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsProviderTestHelper.CLIENT_SECRET;
import static cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsProviderTestHelper.ENCODING_CLIENT_SECRET;
import static cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsProviderTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsProviderTestHelper.mockOAuth2ClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsProviderTestHelper.mockOAuth2ClientDetailsService;
import static cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsProviderTestHelper.mockPasswordEncoder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("클라이언트 인증 제공 클래스 테스트")
class ClientCredentialsAuthenticationProviderTest {

    @Nested
    @DisplayName("인증 진행")
    class AuthenticationProcessing {

        @Nested
        @DisplayName("인증을 요청한 클라이언트를 찾을 수 없을시")
        class WhenClientNotFound {
            private ClientCredentialsToken token;

            private ClientCredentialsAuthenticationProvider provider;

            @BeforeEach
            void setup() {
                this.token = new ClientCredentialsToken(RAW_CLIENT_ID, CLIENT_SECRET);

                OAuth2ClientDetailsService service = mockOAuth2ClientDetailsService().emptyClient().build();
                PasswordEncoder encoder = mockPasswordEncoder().build();

                this.provider = new ClientCredentialsAuthenticationProvider(service, encoder);
            }

            @Test
            @DisplayName("BadCredentialsException 이 발생해야 한다.")
            void shouldThrowsBadCredentialsException() {
                assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
            }
        }

        @Nested
        @DisplayName("클라이언트 아이디가 null 일시")
        class WhenPrincipalIsNull {
            private ClientCredentialsToken token;

            private ClientCredentialsAuthenticationProvider provider;

            @BeforeEach
            void setup() {
                this.token = new ClientCredentialsToken(null, CLIENT_SECRET);

                OAuth2ClientDetailsService service = mockOAuth2ClientDetailsService()
                        .registerClient(mockOAuth2ClientDetails().build()).build();
                PasswordEncoder encoder = mockPasswordEncoder().build();

                this.provider = new ClientCredentialsAuthenticationProvider(service, encoder);
            }

            @Test
            @DisplayName("BadCredentialsException 이 발생해야 한다.")
            void shouldThrowsBadCredentialsException() {
                assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
            }
        }

        @Nested
        @DisplayName("클라이언트 패스워드가 null 일시")
        class WhenCredentialsIsNull {
            private ClientCredentialsToken token;

            private ClientCredentialsAuthenticationProvider provider;

            @BeforeEach
            void setup() {
                this.token = new ClientCredentialsToken(RAW_CLIENT_ID, null);

                OAuth2ClientDetailsService service = mockOAuth2ClientDetailsService()
                        .registerClient(mockOAuth2ClientDetails().build()).build();
                PasswordEncoder encoder = mockPasswordEncoder().build();

                this.provider = new ClientCredentialsAuthenticationProvider(service, encoder);
            }

            @Test
            @DisplayName("BadCredentialsExeption 이 발생해야 한다.")
            void shouldThrowsBadCredentialsException() {
                assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
            }
        }

        @Nested
        @DisplayName("인증을 요청한 클라이언트의 정보를 찾을 수 있을시")
        class WhenClientFound {

            @Nested
            @DisplayName("찾은 클라이언트의 패스워드와 입력받은 패스워드가 일치하지 않을시")
            class WhenPasswordNotMatched {
                private ClientCredentialsToken token;

                private ClientCredentialsAuthenticationProvider provider;

                @BeforeEach
                void setup() {
                    this.token = new ClientCredentialsToken(RAW_CLIENT_ID, CLIENT_SECRET);

                    OAuth2ClientDetails clientDetails = mockOAuth2ClientDetails().configDefault().build();
                    OAuth2ClientDetailsService service = mockOAuth2ClientDetailsService().registerClient(clientDetails).build();
                    PasswordEncoder encoder = mockPasswordEncoder().mismatches().build();

                    this.provider = new ClientCredentialsAuthenticationProvider(service, encoder);
                }

                @Test
                @DisplayName("BadCredentialsException 이 발생해야 한다.")
                void shouldThrowsBadCredentialsException() {
                    assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
                }
            }

            @Nested
            @DisplayName("찾은 클라이언트의 패스워드와 입력받은 패스워드가 일치할시")
            class WhenPasswordMatched {
                private ClientCredentialsToken token;
                private OAuth2ClientDetails clientDetails;

                private ClientCredentialsAuthenticationProvider provider;

                @BeforeEach
                void setup() {
                    this.token = new ClientCredentialsToken(RAW_CLIENT_ID, CLIENT_SECRET);
                    this.clientDetails = mockOAuth2ClientDetails().configDefault().build();

                    OAuth2ClientDetailsService service = mockOAuth2ClientDetailsService().registerClient(clientDetails).build();
                    PasswordEncoder passwordEncoder = mockPasswordEncoder().encode().matches().build();

                    this.provider = new ClientCredentialsAuthenticationProvider(service, passwordEncoder);
                }

                @Test
                @DisplayName("인증 받은 클라이언트의 정보를 저장하여 반환해야 한다.")
                void shouldSaveAuthenticationClient() {
                    Authentication authentication = provider.authenticate(token);

                    assertEquals(clientDetails, authentication.getPrincipal());
                }

                @Test
                @DisplayName("인증 받은 클라이언트의 패스워드를 저장하여 반환해야 한다.")
                void shouldSaveClientSecret() {
                    Authentication authentication = provider.authenticate(token);

                    assertEquals(ENCODING_CLIENT_SECRET, authentication.getCredentials());
                }

                @Test
                @DisplayName("권한 정보는 빈 배열로 저장해야 한다.")
                void shouldSaveAuthoritiesEmptyList() {
                    Authentication authentication = provider.authenticate(token);

                    assertEquals(Collections.emptyList(), authentication.getAuthorities());
                }

                @Test
                @DisplayName("인증 여부는 true 가 반환되어야 한다.")
                void shouldAuthenticatedReturnsTrue() {
                    Authentication authentication = provider.authenticate(token);

                    assertTrue(authentication.isAuthenticated());
                }
            }
        }

        @Nested
        @DisplayName("인증 중 예상하지 못한 예외가 발생했을시")
        class WhenThrowsRuntimeException {
            private ClientCredentialsToken token;

            private ClientCredentialsAuthenticationProvider provider;

            @BeforeEach
            void setup() {
                this.token = new ClientCredentialsToken(RAW_CLIENT_ID, CLIENT_SECRET);

                OAuth2ClientDetailsService service = mockOAuth2ClientDetailsService().configThrows().build();
                this.provider = new ClientCredentialsAuthenticationProvider(service, mockPasswordEncoder().build());
            }

            @Test
            @DisplayName("발생한 예외를 InternalAuthenticationServiceException 으로 감싸 반환해야 한다.")
            void shouldThrowsExceptionWithInternalAuthenticationServiceException() {
                assertThrows(InternalAuthenticationServiceException.class, () -> provider.authenticate(token));
            }
        }
    }

}