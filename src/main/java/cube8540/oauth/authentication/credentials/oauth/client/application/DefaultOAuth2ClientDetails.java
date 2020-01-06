package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

@ToString
@EqualsAndHashCode
public class DefaultOAuth2ClientDetails implements OAuth2ClientDetails {

    private String clientId;
    private String clientSecret;
    private String clientName;
    private Set<URI> registeredRedirectURI;
    private Set<AuthorizationGrantType> authorizedGrantType;
    private Set<OAuth2ScopeId> scope;
    private Integer accessTokenValiditySeconds;
    private Integer refreshTokenValiditySeconds;

    public DefaultOAuth2ClientDetails(OAuth2Client client) {
        this.clientId = client.getClientId().getValue();
        this.clientSecret = client.getSecret().getSecret();
        this.clientName = client.getClientName();
        this.registeredRedirectURI = Collections.unmodifiableSet(client.getRedirectURI());
        this.authorizedGrantType = Collections.unmodifiableSet(client.getGrantType());
        this.scope = Collections.unmodifiableSet(client.getScope());
        this.accessTokenValiditySeconds = Double.valueOf(client.getAccessTokenValidity().toSeconds()).intValue();
        this.refreshTokenValiditySeconds = Double.valueOf(client.getRefreshTokenValidity().toSeconds()).intValue();
    }

    @Override
    public String clientId() {
        return clientId;
    }

    @Override
    public String clientSecret() {
        return clientSecret;
    }

    @Override
    public String clientName() {
        return clientName;
    }

    @Override
    public Set<URI> registeredRedirectURI() {
        return registeredRedirectURI;
    }

    @Override
    public Set<AuthorizationGrantType> authorizedGrantType() {
        return authorizedGrantType;
    }

    @Override
    public Set<OAuth2ScopeId> scope() {
        return scope;
    }

    @Override
    public Integer accessTokenValiditySeconds() {
        return accessTokenValiditySeconds;
    }

    @Override
    public Integer refreshTokenValiditySeconds() {
        return refreshTokenValiditySeconds;
    }
}
