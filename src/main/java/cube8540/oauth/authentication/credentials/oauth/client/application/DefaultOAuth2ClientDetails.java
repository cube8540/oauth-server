package cube8540.oauth.authentication.credentials.oauth.client.application;

import com.fasterxml.jackson.annotation.JsonIgnore;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Singular;
import lombok.ToString;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.time.Duration;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Builder
@ToString
@EqualsAndHashCode
@AllArgsConstructor
public class DefaultOAuth2ClientDetails implements OAuth2ClientDetails, CredentialsContainer {

    private String clientId;

    @JsonIgnore
    private String clientSecret;

    private String clientName;

    @Singular("registeredRedirectURI")
    private Set<URI> registeredRedirectURI;

    @Singular("authorizedGrantType")
    private Set<AuthorizationGrantType> authorizedGrantType;

    @Singular("scope")
    private Set<String> scope;

    private String owner;

    private Integer accessTokenValiditySeconds;

    private Integer refreshTokenValiditySeconds;

    public static DefaultOAuth2ClientDetails of(OAuth2Client client) {
        Set<String> scope = Optional.ofNullable(client.getScope()).orElse(Collections.emptySet())
                .stream().map(OAuth2ScopeId::getValue).collect(Collectors.toSet());
        Long tokenValidity = Optional.ofNullable(client.getAccessTokenValidity()).map(Duration::toSeconds).orElse(0L);
        Long refreshValidity = Optional.ofNullable(client.getRefreshTokenValidity()).map(Duration::toSeconds).orElse(0L);

        return builder().clientId(client.getClientId().getValue())
                .clientSecret(client.getSecret())
                .owner(Optional.ofNullable(client.getOwner()).map(UserEmail::getValue).orElse(null))
                .scope(scope)
                .accessTokenValiditySeconds(Double.valueOf(tokenValidity).intValue())
                .refreshTokenValiditySeconds(Double.valueOf(refreshValidity).intValue())
                .registeredRedirectURI(Optional.ofNullable(client.getRedirectURI()).orElse(Collections.emptySet()))
                .authorizedGrantType(Optional.ofNullable(client.getGrantType()).orElse(Collections.emptySet())).build();
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
