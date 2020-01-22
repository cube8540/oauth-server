package cube8540.oauth.authentication.credentials.oauth.client.provider;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 인증 제공 클래스 테스트")
class ClientCredentialsAuthenticationProviderTest {

    private static final String CLIENT_ID = "CLIENT_ID";
    private static final String CLIENT_SECRET = "CLIENT_SECRET";
    private static final String ENCODING_CLIENT_SECRET = "ENCODING_CLIENT_SECRET";

    private OAuth2ClientDetailsService service;
    private PasswordEncoder encoder;

    private ClientCredentialsAuthenticationProvider provider;

    @BeforeEach
    void setup() {
        this.service = mock(OAuth2ClientDetailsService.class);
        this.encoder = mock(PasswordEncoder.class);
        this.provider = new ClientCredentialsAuthenticationProvider(service, encoder);
    }

    @Nested
    @DisplayName("인증을 지원하는 토큰 타입 테스트")
    class SupportedTokenType {

        @Nested
        @DisplayName("매개변수로 받은 타입이 ClientCredentialsToken이 아닐시")
        class WhenArgumentTypeIsNotClientCredentialsToken {

            @Test
            @DisplayName("지원 여부는 false가 반환되어야 한다.")
            void shouldSupportedReturnsFalse() {
                assertFalse(provider.supports(Object.class));
                assertFalse(provider.supports(Authentication.class));
            }
        }

        @Nested
        @DisplayName("매개 변수로 받은 타입이 ClientCredentialsToken일시")
        class WhenArgumentTypeIsClientCredentialsToken {

            @Test
            @DisplayName("지원 여부는 true가 반환되어야 한다.")
            void shouldSupportedReturnsTrue() {
                assertTrue(provider.supports(ClientCredentialsToken.class));
            }
        }
    }

    @Nested
    @DisplayName("인증 진행")
    class AuthenticationProcessing {

        private ClientCredentialsToken token;

        @BeforeEach
        void setup() {
            this.token = new ClientCredentialsToken(CLIENT_ID, CLIENT_SECRET);
        }

        @Nested
        @DisplayName("인증을 요청한 클라이언트를 찾을 수 없을시")
        class WhenClientNotFound {

            @BeforeEach
            void setup() {
                when(service.loadClientDetailsByClientId(any())).thenThrow(new OAuth2ClientNotFoundException("client not found"));
            }

            @Test
            @DisplayName("BadCredentialsExeption이 발생해야 한다.")
            void shouldThrowsBadCredentialsException() {
                assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
            }
        }

        @Nested
        @DisplayName("인증을 요청한 클라이언트의 정보를 찾을 수 있을시")
        class WhenClientFound {
            private OAuth2ClientDetails details;

            @BeforeEach
            void setup() {
                this.details = mock(OAuth2ClientDetails.class);
                when(details.clientId()).thenReturn(CLIENT_ID);
                when(details.clientSecret()).thenReturn(ENCODING_CLIENT_SECRET);
                when(service.loadClientDetailsByClientId(CLIENT_ID)).thenReturn(details);
            }

            @Nested
            @DisplayName("찾은 클라이언트의 패스워드와 입력받은 패스워드가 일치하지 않을시")
            class WhenPasswordNotMatched {
                @BeforeEach
                void setup() {
                    when(encoder.matches(ENCODING_CLIENT_SECRET,CLIENT_SECRET)).thenReturn(false);
                }

                @Test
                @DisplayName("BadCredentialsException이 발생해야 한다.")
                void shouldThrowsBadCredentialsException() {
                    assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
                }
            }

            @Nested
            @DisplayName("찾은 클라이언트의 패스워드와 입력받은 패스워드가 일치할시")
            class WhenPasswordMatched {
                @BeforeEach
                void setup() {
                    when(encoder.matches(ENCODING_CLIENT_SECRET, CLIENT_SECRET)).thenReturn(true);
                }

                @Test
                @DisplayName("인증 받은 클라이언트의 정보를 저장하여 반환해야 한다.")
                void shouldSaveAuthenticationClient() {
                    Authentication authentication = provider.authenticate(token);

                    assertEquals(details, authentication.getPrincipal());
                }

                @Test
                @DisplayName("인증 받은 클라이언트의 원래 패스워드를 저장하여 반환해야 한다.")
                void shouldSaveOriginalClientSecret() {
                    Authentication authentication = provider.authenticate(token);

                    assertEquals(CLIENT_SECRET, authentication.getCredentials());
                }

                @Test
                @DisplayName("권한 정보는 빈 배열로 저장해야 한다.")
                void shouldSaveAuthoritiesEmptyList() {
                    Authentication authentication = provider.authenticate(token);

                    assertEquals(Collections.emptyList(), authentication.getAuthorities());
                }

                @Test
                @DisplayName("인증 여부는 true가 반환되어야 한다.")
                void shouldAuthenticatedReturnsTrue() {
                    Authentication authentication = provider.authenticate(token);

                    assertTrue(authentication.isAuthenticated());
                }
            }
        }

        @Nested
        @DisplayName("인증 중 예상하지 못한 예외가 발생했을시")
        class WhenThrowsRuntimeException {

            @BeforeEach
            void setup() {
                when(service.loadClientDetailsByClientId(any())).thenThrow(new RuntimeException());
            }

            @Test
            @DisplayName("발생한 예외를 InternalAuthenticationServiceException으로 감싸 반환해야 한다.")
            void shouldThrowsExceptionWithInternalAuthenticationServiceException() {
                assertThrows(InternalAuthenticationServiceException.class, () -> provider.authenticate(token));
            }
        }
    }

}