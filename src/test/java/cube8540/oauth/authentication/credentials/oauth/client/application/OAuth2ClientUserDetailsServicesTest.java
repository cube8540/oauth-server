package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 클라이언트 스프링 시큐리티 UserDetailsServices 구현 클래스 테스트")
class OAuth2ClientUserDetailsServicesTest {

    private OAuth2ClientDetailsService clientDetailsService;
    private OAuth2ClientDetails clientDetails;

    private OAuth2ClientUserDetailsServices service;

    @BeforeEach
    void setup() {
        this.clientDetailsService = mock(OAuth2ClientDetailsService.class);
        this.clientDetails = mock(OAuth2ClientDetails.class);

        this.service = new OAuth2ClientUserDetailsServices(clientDetailsService);
    }

    @Nested
    @DisplayName("저장소의 클라이언트를 로딩")
    class WhenLoadingClient {
        private String clientId = "CLIENT-ID";
        private String secret = "SECRET";

        @BeforeEach
        void setup() {
            when(clientDetails.clientId()).thenReturn(clientId);
            when(clientDetails.clientSecret()).thenReturn(secret);
        }

        @Nested
        @DisplayName("저장소에 클라이언트가 없을시")
        class WhenNotFoundClient {

            @BeforeEach
            void setup() {
                when(clientDetailsService.loadClientDetailsByClientId("CLIENT-ID"))
                        .thenThrow(new OAuth2ClientNotFoundException("client not found"));
            }

            @Test
            @DisplayName("UsernameNotFoundException이 발생해야 한다.")
            void shouldThrowsUsernameNotFoundException() {
                assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername("CLIENT-ID"));
            }

            @Test
            @DisplayName("발생한 예외 객체에 OAuth2ClientNotFoundException 객체가 포함되어 있어야 한다.")
            void shouldContainsOAuth2ClientNotFoundException() {
                UsernameNotFoundException exception = assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername("CLIENT-ID"));
                assertEquals(OAuth2ClientNotFoundException.class, exception.getCause().getClass());
            }
        }

        @Nested
        @DisplayName("저장소에 클라이언트가 있을시")
        class WhenFoundClient {

            @BeforeEach
            void setup() {
                when(clientDetailsService.loadClientDetailsByClientId("CLIENT-ID")).thenReturn(clientDetails);
            }

            @Test
            @DisplayName("저장소에서 찾은 클라이언트의 아이디를 반환해야 한다.")
            void shouldReturnsClientId() {
                UserDetails result = service.loadUserByUsername("CLIENT-ID");

                assertEquals(clientId, result.getUsername());
            }

            @Test
            @DisplayName("저장소에서 찾은 클라이언트의 패스워드를 반환해야 한다.")
            void shouldReturnsClientSecret() {
                UserDetails result = service.loadUserByUsername("CLIENT-ID");

                assertEquals(secret, result.getPassword());
            }

            @Test
            @DisplayName("권한은 빈 배열로 반환되어야 한다.")
            void shouldAuthoritiesIsEmptySet() {
                UserDetails result = service.loadUserByUsername("CLIENT-ID");

                assertEquals(Collections.emptySet(), result.getAuthorities());
            }
        }
    }

}