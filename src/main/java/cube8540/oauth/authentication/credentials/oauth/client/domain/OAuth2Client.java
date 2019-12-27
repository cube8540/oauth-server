package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.oauth.authentication.credentials.oauth.client.converter.OAuth2GrantTypeConverter;
import cube8540.oauth.authentication.credentials.oauth.client.converter.OAuth2RedirectURIConverter;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

import javax.persistence.AttributeOverride;
import javax.persistence.CascadeType;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.ElementCollection;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import java.net.URI;
import java.time.Duration;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "oauth2_clients")
public class OAuth2Client extends AbstractAggregateRoot<OAuth2Client> {

    public static final Duration DEFAULT_ACCESS_TOKEN_VALIDITY = Duration.ofMinutes(10);
    public static final Duration DEFAULT_REFRESH_TOKEN_VALIDITY = Duration.ofHours(2);

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "client_id", length = 32))
    private OAuth2ClientId clientId;

    @Column(name = "client_secret", length = 32, nullable = false)
    private String secret;

    @Column(name = "client_name", length = 32, nullable = false)
    private String clientName;

    @ElementCollection
    @Column(name = "redirect_uri", length = 128, nullable = false)
    @CollectionTable(name = "oauth2_client_redirect_uri", joinColumns = @JoinColumn(name = "client_id", nullable = false))
    @Convert(converter = OAuth2RedirectURIConverter.class)
    private Set<URI> redirectURI;

    @ElementCollection
    @Column(name = "grant_type", length = 32, nullable = false)
    @CollectionTable(name = "oauth2_client_grant_type", joinColumns = @JoinColumn(name = "client_id", nullable = false))
    @Convert(converter = OAuth2GrantTypeConverter.class)
    private Set<OAuth2ClientGrantType> grantType;

    @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinTable(name = "oauth2_client_scope", joinColumns = @JoinColumn(name = "client_id"), inverseJoinColumns = @JoinColumn(name = "scope_id"))
    private Set<OAuth2Scope> scope;

    @Column(name = "access_token_validity", nullable = false)
    private Duration accessTokenValidity;

    @Column(name = "refresh_token_validity", nullable = false)
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
