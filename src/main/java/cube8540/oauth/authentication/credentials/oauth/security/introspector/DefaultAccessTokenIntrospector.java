package cube8540.oauth.authentication.credentials.oauth.security.introspector;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetailsService;
import cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import lombok.Setter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class DefaultAccessTokenIntrospector implements OpaqueTokenIntrospector {

    private final OAuth2AccessTokenDetailsService accessTokenService;

    private final AuthenticationProvider authenticationProvider;

    @Setter
    private String clientId;

    @Setter
    private String clientSecret;

    public DefaultAccessTokenIntrospector(OAuth2AccessTokenDetailsService accessTokenService, AuthenticationProvider authenticationProvider) {
        this.accessTokenService = accessTokenService;
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AccessTokenDetails accessToken = readAccessToken(token);

        Authentication clientCredentials = clientAuthentication(clientId, clientSecret);
        if (!clientCredentials.getName().equals(accessToken.getClientId())) {
            throw new OAuth2IntrospectionException("client is different");
        }

        return new DefaultOAuth2AuthenticatedPrincipal(accessToken.getUsername(), convertClaims(accessToken), extractAuthorities(accessToken));
    }

    private OAuth2AccessTokenDetails readAccessToken(String token) {
        try {
            OAuth2AccessTokenDetails accessToken = accessTokenService.readAccessToken(token);
            if (accessToken.isExpired()) {
                throw new OAuth2IntrospectionException(token + " is not active");
            }
            return accessToken;
        } catch (OAuth2AccessTokenNotFoundException e) {
            throw new OAuth2IntrospectionException(token + " is not active", e);
        }
    }

    private Map<String, Object> convertClaims(OAuth2AccessTokenDetails accessToken) {
        Map<String, Object> claims = new HashMap<>();

        if (accessToken.getClientId() != null) {
            claims.put(OAuth2IntrospectionClaimNames.CLIENT_ID, accessToken.getClientId());
        }
        if (accessToken.getScopes() != null && !accessToken.getScopes().isEmpty()) {
            claims.put(OAuth2IntrospectionClaimNames.SCOPE, extractAuthorities(accessToken));
        }
        if (accessToken.getAdditionalInformation() != null) {
            accessToken.getAdditionalInformation().forEach(claims::put);
        }

        return claims;
    }

    private Collection<GrantedAuthority> extractAuthorities(OAuth2AccessTokenDetails accessToken) {
        if (accessToken.getScopes() != null && !accessToken.getScopes().isEmpty()) {
            return accessToken.getScopes().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        } else {
            return Collections.emptySet();
        }
    }

    private Authentication clientAuthentication(String clientId, String clientSecret) {
        try {
            return authenticationProvider.authenticate(new ClientCredentialsToken(clientId, clientSecret));
        } catch (Exception e) {
            throw new OAuth2IntrospectionException("bad client credentials", e);
        }
    }
}
