package cube8540.oauth.authentication.credentials.oauth.authorize.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 리다이렉트 주소 Resolver 클래스 테스트")
class DefaultRedirectResolverTest {

    private DefaultRedirectResolver resolver;

    @BeforeEach
    void setup() {
        this.resolver = new DefaultRedirectResolver();
    }

    @Nested
    @DisplayName("리다이렉트 주소 추출")
    class ExtractRedirectURI {

        @Nested
        @DisplayName("클라이언트에 등록된 리다이렉트 주소가 한개일시")
        class WhenSingleRedirectUriRegisteredOnTheClient {

            private OAuth2ClientDetails clientDetails;

            @BeforeEach
            void setup() {
                Set<URI> redirectURI = new HashSet<>();
                this.clientDetails = mock(OAuth2ClientDetails.class);

                redirectURI.add(URI.create("http://localhost:8080"));

                when(this.clientDetails.getRegisteredRedirectUris()).thenReturn(redirectURI);
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 주소가 null일시")
            class WhenRequestingUriIsNull {

                @Test
                @DisplayName("클라이언트에 등록된 주소가 반환되어야 한다.")
                void shouldReturnsRedirectUriStoredInClient() {
                    URI result = resolver.resolveRedirectURI(null, clientDetails);

                    assertEquals(URI.create("http://localhost:8080"), result);
                }
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 주소가 클라이언트에 등록되지 않았을시")
            class WhenRequestingRedirectNotRegisteredInClient {

                @Test
                @DisplayName("RedirectMismatchException이 발생해야 한다.")
                void shouldThrowsRedirectMismatchException() {
                    String uri = "http://localhost:8085";
                    assertThrows(RedirectMismatchException.class, () -> resolver.resolveRedirectURI(uri, clientDetails));
                }
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 주소가 클라이언트에 등록되어 있을시")
            class WhenRequestingRedirectRegisteredOnTheClient {

                @Test
                @DisplayName("요청 받은 리다이렉트 주소를 반환해야 한다.")
                void shouldReturnsRequestingRedirectURI() {
                    String uri = "http://localhost:8080";

                    URI result = resolver.resolveRedirectURI(uri, clientDetails);
                    assertEquals(URI.create(uri), result);
                }
            }
        }

        @Nested
        @DisplayName("클라이언트에 등록된 리다이렉트 주소가 여러개일시")
        class WhenMultipleRedirectUriRegisteredOnTheClient {

            private OAuth2ClientDetails clientDetails;

            @BeforeEach
            void setup() {
                Set<URI> redirectURI = new HashSet<>();
                this.clientDetails = mock(OAuth2ClientDetails.class);

                redirectURI.add(URI.create("http://localhost:8080"));
                redirectURI.add(URI.create("http://localhost:8081"));
                redirectURI.add(URI.create("http://localhost:8082"));

                when(this.clientDetails.getRegisteredRedirectUris()).thenReturn(redirectURI);
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 주소가 null일시")
            class WhenRequestingRedirectUriIsNull {

                @Test
                @DisplayName("InvalidRequestException이 발생해야 한다.")
                void shouldThrowsInvalidRequestException() {
                    assertThrows(InvalidRequestException.class, () -> resolver.resolveRedirectURI(null, clientDetails));
                }

                @Test
                @DisplayName("에러 코드는 INVALID_REQUEST 이어야 한다.")
                void shouldErrorCodeIsInvalidRequest() {
                    OAuth2Error error = assertThrows(InvalidRequestException.class, () -> resolver.resolveRedirectURI(null, clientDetails))
                            .getError();

                    assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
                }
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 주소가 클라이언트에 등록되지 않았을시")
            class WhenRequestingRedirectNotRegisteredInClient {

                @Test
                @DisplayName("RedirectMismatchException이 발생해야 한다.")
                void shouldThrowsRedirectMismatchException() {
                    String uri = "http://localhost:8085";
                    assertThrows(RedirectMismatchException.class, () -> resolver.resolveRedirectURI(uri, clientDetails));
                }
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 주소가 클라이언트에 등록되어 있을시")
            class WhenRequestingRedirectRegisteredOnTheClient {

                @Test
                @DisplayName("요청 받은 리다이렉트 주소를 반환해야 한다.")
                void shouldReturnsRequestingRedirectURI() {
                    String uri = "http://localhost:8080";

                    URI result = resolver.resolveRedirectURI(uri, clientDetails);
                    assertEquals(URI.create(uri), result);
                }
            }
        }
    }

}