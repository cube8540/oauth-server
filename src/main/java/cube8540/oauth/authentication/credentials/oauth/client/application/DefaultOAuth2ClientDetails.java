package cube8540.oauth.authentication.credentials.oauth.client.application;

import com.fasterxml.jackson.annotation.JsonIgnore;
import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientOwner;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
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
    private Set<URI> registeredRedirectUris;

    @Singular("authorizedGrantType")
    private Set<AuthorizationGrantType> authorizedGrantTypes;

    @Singular("scope")
    private Set<String> scopes;

    private String owner;

    private Integer accessTokenValiditySeconds;

    private Integer refreshTokenValiditySeconds;

    public static DefaultOAuth2ClientDetails of(OAuth2Client client) {
        Set<String> scope = Optional.ofNullable(client.getScopes()).orElse(Collections.emptySet())
                .stream().map(AuthorityCode::getValue).collect(Collectors.toSet());
        Long tokenValidity = Optional.ofNullable(client.getAccessTokenValidity()).map(Duration::toSeconds).orElse(0L);
        Long refreshValidity = Optional.ofNullable(client.getRefreshTokenValidity()).map(Duration::toSeconds).orElse(0L);

        return builder().clientId(client.getClientId().getValue())
                .clientSecret(client.getSecret())
                .clientName(client.getClientName())
                .owner(Optional.ofNullable(client.getOwner()).map(ClientOwner::getValue).orElse(null))
                .scopes(scope)
                .accessTokenValiditySeconds(tokenValidity.intValue())
                .refreshTokenValiditySeconds(refreshValidity.intValue())
                .registeredRedirectUris(Optional.ofNullable(client.getRedirectUris()).orElse(Collections.emptySet()))
                .authorizedGrantTypes(Optional.ofNullable(client.getGrantTypes()).orElse(Collections.emptySet())).build();
    }

    @Override
    public void eraseCredentials() {
        this.clientSecret = null;
    }
}
