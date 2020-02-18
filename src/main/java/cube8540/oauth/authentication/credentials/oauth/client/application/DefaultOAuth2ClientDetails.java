package cube8540.oauth.authentication.credentials.oauth.client.application;

import com.fasterxml.jackson.annotation.JsonIgnore;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@ToString
@EqualsAndHashCode
public class DefaultOAuth2ClientDetails implements OAuth2ClientDetails, CredentialsContainer {

    private String clientId;

    @JsonIgnore
    private String clientSecret;

    private String clientName;

    private Set<URI> registeredRedirectURI;

    private Set<AuthorizationGrantType> authorizedGrantType;

    private Set<String> scope;

    private String owner;

    private Integer accessTokenValiditySeconds;

    private Integer refreshTokenValiditySeconds;

    public DefaultOAuth2ClientDetails(OAuth2Client client) {
        this.clientId = client.getClientId().getValue();
        this.clientSecret = client.getSecret();
        this.clientName = client.getClientName();
        this.registeredRedirectURI = Collections.unmodifiableSet(Optional.ofNullable(client.getRedirectURI()).orElse(Collections.emptySet()));
        this.authorizedGrantType = Collections.unmodifiableSet(Optional.ofNullable(client.getGrantType()).orElse(Collections.emptySet()));
        this.scope = Optional.ofNullable(client.getScope()).orElse(Collections.emptySet()).stream()
                .map(OAuth2ScopeId::getValue).collect(Collectors.toUnmodifiableSet());
        this.owner = client.getOwner().getValue();
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
    public Set<String> scope() {
        return scope;
    }

    @Override
    public String owner() {
        return owner;
    }

    @Override
    public Integer accessTokenValiditySeconds() {
        return accessTokenValiditySeconds;
    }

    @Override
    public Integer refreshTokenValiditySeconds() {
        return refreshTokenValiditySeconds;
    }

    @Override
    public void eraseCredentials() {
        this.clientSecret = null;
    }
}
