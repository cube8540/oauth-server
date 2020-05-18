package cube8540.oauth.authentication.credentials.oauth.security.introspector;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OpaqueTokenIntrospectorTestSupport {

    static final String RAW_TOKEN = "TOKEN";

    static final String RAW_PRINCIPAL_NAME = "principal";
    static final List<String> RAW_SCOPE_AUTHORITY = Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3");
    static final List<String> RAW_ROLE_AUTHORITY = Arrays.asList("AUTH-1", "AUTH-2", "AUTH-3");

    static final Collection<GrantedAuthority> ROLE_AUTHORITIES = RAW_ROLE_AUTHORITY.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());

    static MockOAuthAuthenticatedPrincipal mockOAuthAuthenticatedPrincipal() {
        return new MockOAuthAuthenticatedPrincipal();
    }

    static MockUserDetailsService mockUserDetailsService() {
        return new MockUserDetailsService();
    }

    static MockUser mockUser() {
        return new MockUser();
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

    static class MockUserDetailsService {
        private UserDetailsService service;

        private MockUserDetailsService() {
            this.service = mock(UserDetailsService.class);
        }

        MockUserDetailsService registerUser(User user) {
            when(service.loadUserByUsername(RAW_PRINCIPAL_NAME)).thenReturn(user);
            return this;
        }

        UserDetailsService build() {
            return service;
        }
    }

    static class MockUser {
        private User user;

        private MockUser() {
            this.user = mock(User.class);
        }

        MockUser configAuthorities(Collection<GrantedAuthority> authorities) {
            when(user.getAuthorities()).thenReturn(authorities);
            return this;
        }

        User build() {
            return user;
        }
    }

}
