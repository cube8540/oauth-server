package cube8540.oauth.authentication.credentials.oauth.client.domain;

import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.net.URI;
import java.time.Duration;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Getter
@ToString
@EqualsAndHashCode
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuth2Client {

    public static final Duration DEFAULT_ACCESS_TOKEN_VALIDITY = Duration.ofMinutes(10);
    public static final Duration DEFAULT_REFRESH_TOKEN_VALIDITY = Duration.ofHours(2);

    private OAuth2ClientId clientId;

    private String secret;

    private String clientName;

    private Set<URI> redirectURI;

    private Set<String> resourceId;

    private Set<OAuth2ClientGrantType> grantType;

    private Set<OAuth2Scope> scope;

    private Duration accessTokenValidity;

    private Duration refreshTokenValidity;

    public OAuth2Client(String clientId, String secret, String clientName) {
        this.clientId = new OAuth2ClientId(clientId);
        this.secret = secret;
        this.clientName = clientName;
        this.accessTokenValidity = DEFAULT_ACCESS_TOKEN_VALIDITY;
        this.refreshTokenValidity = DEFAULT_REFRESH_TOKEN_VALIDITY;
    }

    public void addRedirectURI(URI uri) {
        if (this.redirectURI == null) {
            this.redirectURI = new HashSet<>();
        }
        this.redirectURI.add(uri);
    }

    public void removeRedirectURI(URI redirectURI) {
        Optional.ofNullable(this.redirectURI)
                .ifPresent(uris -> uris.remove(redirectURI));
    }

    public void addResourceId(String resourceId) {
        if (this.resourceId == null) {
            this.resourceId = new HashSet<>();
        }
        this.resourceId.add(resourceId);
    }

    public void removeResourceId(String resourceId) {
        Optional.ofNullable(this.resourceId)
                .ifPresent(ids -> ids.remove(resourceId));
    }

    public void addGrantType(OAuth2ClientGrantType grantType) {
        if (this.grantType == null) {
            this.grantType = new HashSet<>();
        }
        this.grantType.add(grantType);
    }

    public void removeGrantType(OAuth2ClientGrantType grantType) {
        Optional.ofNullable(this.grantType)
                .ifPresent(types -> types.remove(grantType));
    }

    public void addScope(OAuth2Scope scope) {
        if (this.scope == null) {
            this.scope = new HashSet<>();
        }
        this.scope.add(scope);
    }

    public void removeScope(OAuth2Scope scope) {
        Optional.ofNullable(this.scope)
                .ifPresent(scopes -> scopes.remove(scope));
    }
}
