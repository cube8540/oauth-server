package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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

    @Test
    @DisplayName("요청 받은 URI가 null 이며 클라이언트에 등록된 리다이렉트 주소가 한개일 때")
    void whenRequestedUriIsNullAndSingleRedirectUriRegisteredOnClient() {
        Set<URI> redirectURI = new HashSet<>();
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);

        redirectURI.add(URI.create("http://localhost:8080"));
        when(clientDetails.getRegisteredRedirectUris()).thenReturn(redirectURI);

        URI result = resolver.resolveRedirectURI(null, clientDetails);
        assertEquals(URI.create("http://localhost:8080"), result);
    }

    @Test
    @DisplayName("요청 받은 URI가 null 이며 클라이언트에 등록된 리다이렉트 주소가 두개 이상일 때")
    void whenRequestedUriIsNullAndMoreThanOneRegisteredUriOnClient() {
        Set<URI> redirectURI = new HashSet<>();
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);

        redirectURI.add(URI.create("http://localhost:8080"));
        redirectURI.add(URI.create("http://localhost:8081"));
        redirectURI.add(URI.create("http://localhost:8082"));
        when(clientDetails.getRegisteredRedirectUris()).thenReturn(redirectURI);

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> resolver.resolveRedirectURI(null, clientDetails)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("요청 받은 URI가 등록 되지 않은 URI 일 때")
    void whenRequestedUriIsNotRegisteredInClient() {
        Set<URI> redirectURI = new HashSet<>();
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);

        redirectURI.add(URI.create("http://localhost:8080"));
        redirectURI.add(URI.create("http://localhost:8081"));
        redirectURI.add(URI.create("http://localhost:8082"));
        when(clientDetails.getRegisteredRedirectUris()).thenReturn(redirectURI);

        String uri = "http://localhost:8085";
        assertThrows(RedirectMismatchException.class, () -> resolver.resolveRedirectURI(uri, clientDetails));
    }

    @Test
    @DisplayName("요청 받은 URI가 등록 되어 있는 URI 일 떄")
    void whenRequestedUriIsRegisteredInClient() {
        Set<URI> redirectURI = new HashSet<>();
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);

        redirectURI.add(URI.create("http://localhost:8080"));
        redirectURI.add(URI.create("http://localhost:8081"));
        redirectURI.add(URI.create("http://localhost:8082"));
        when(clientDetails.getRegisteredRedirectUris()).thenReturn(redirectURI);

        String uri = "http://localhost:8080";
        URI result = resolver.resolveRedirectURI(uri, clientDetails);
        assertEquals(URI.create(uri), result);
    }
}