package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientGrantType;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ScopeId;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.net.URI;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

@ToString
@EqualsAndHashCode
public class DefaultOAuth2ClientDetails implements OAuth2ClientDetails {

    private String clientId;
    private String clientSecret;
    private String clientName;
    private Set<URI> registeredRedirectURI;
    private Set<OAuth2ClientGrantType> authorizedGrantType;
    private Set<OAuth2ScopeId> scope;
    private Integer accessTokenValiditySeconds;
    private Integer refreshTokenValiditySeconds;

    public DefaultOAuth2ClientDetails(OAuth2Client client) {
        this.clientId = client.getClientId().getValue();
        this.clientSecret = client.getSecret();
        this.clientName = client.getClientName();
        this.registeredRedirectURI = Collections.unmodifiableSet(client.getRedirectURI());
        this.authorizedGrantType = Collections.unmodifiableSet(client.getGrantType());
        this.scope = client.getScope().stream().map(OAuth2Scope::getId).collect(Collectors.toUnmodifiableSet());
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
    public Set<OAuth2ClientGrantType> authorizedGrantType() {
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
