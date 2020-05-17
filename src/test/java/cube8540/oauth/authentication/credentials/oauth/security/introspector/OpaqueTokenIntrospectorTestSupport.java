package cube8540.oauth.authentication.credentials.oauth.security.introspector;

import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OpaqueTokenIntrospectorTestSupport {

    public static final String RAW_TOKEN = "TOKEN";

    public static final String RAW_PRINCIPAL_NAME = "principal";
    public static final List<String> RAW_AUTHORITIES = Arrays.asList("AUTH-1", "AUTH-2", "AUTH-3");

    public static MockOAuthAuthenticatedPrincipal mockOAuthAuthenticatedPrincipal() {
        return new MockOAuthAuthenticatedPrincipal();
    }

    static class MockOAuthAuthenticatedPrincipal {
        private OAuth2AuthenticatedPrincipal principal;

        private MockOAuthAuthenticatedPrincipal() {
            this.principal = mock(OAuth2AuthenticatedPrincipal.class);
        }

        public MockOAuthAuthenticatedPrincipal configDefault() {
            when(principal.getAttributes()).thenReturn(Collections.emptyMap());
            return this;
        }

        public MockOAuthAuthenticatedPrincipal configUsernameInAttribute(String username) {
            when(principal.getAttribute(OAuth2IntrospectionClaimNames.USERNAME)).thenReturn(username);
            return this;
        }

        public MockOAuthAuthenticatedPrincipal configAuthoritiesInAttribute(List<String> authorities) {
            when(principal.getAttribute(OAuth2IntrospectionClaimNames.SCOPE)).thenReturn(authorities);
            return this;
        }

        public MockOAuthAuthenticatedPrincipal configAttributes(Map<String, Object> attributes) {
            when(principal.getAttributes()).thenReturn(attributes);
            return this;
        }

        public OAuth2AuthenticatedPrincipal build() {
            return principal;
        }
    }

}
