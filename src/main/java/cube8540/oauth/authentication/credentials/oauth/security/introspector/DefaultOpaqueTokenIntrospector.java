package cube8540.oauth.authentication.credentials.oauth.security.introspector;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DefaultOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final OpaqueTokenIntrospector delegate;
    private final UserDetailsService userDetailsService;

    public DefaultOpaqueTokenIntrospector(OpaqueTokenIntrospector delegate, UserDetailsService userDetailsService) {
        this.delegate = delegate;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal principal = this.delegate.introspect(token);
        return new DefaultOAuth2AuthenticatedPrincipal(principal.getAttribute(OAuth2IntrospectionClaimNames.USERNAME),
                principal.getAttributes(), extractAuthorities(principal));
    }

    private Collection<GrantedAuthority> extractAuthorities(OAuth2AuthenticatedPrincipal principal) {
        Collection<String> roles = principal.getAttribute(OAuth2IntrospectionClaimNames.USERNAME) != null ?
                getUserAuthorities(principal) : Collections.emptySet();
        Collection<String> scopes = getUserScopes(principal);

        return Stream.concat(roles.stream(), scopes.stream()).map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
    }

    private Collection<String> getUserScopes(OAuth2AuthenticatedPrincipal principal) {
        Collection<String> scopes = principal.getAttribute(OAuth2IntrospectionClaimNames.SCOPE);

        return Optional.ofNullable(scopes).orElse(Collections.emptySet());
    }

    private Collection<String> getUserAuthorities(OAuth2AuthenticatedPrincipal principal) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(principal.getAttribute(OAuth2IntrospectionClaimNames.USERNAME));

        return Optional.ofNullable(userDetails.getAuthorities()).orElse(Collections.emptySet()).stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
    }
}
