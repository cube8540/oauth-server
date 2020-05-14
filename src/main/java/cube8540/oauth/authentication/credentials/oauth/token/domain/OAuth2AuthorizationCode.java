package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.converter.RedirectUriConverter;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

import javax.persistence.AttributeOverride;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.ElementCollection;
import javax.persistence.Embedded;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Table;
import javax.persistence.Transient;
import java.net.URI;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "oauth2_authorization_code")
public class OAuth2AuthorizationCode extends AbstractAggregateRoot<OAuth2AuthorizationCode> {

    @Transient
    @Setter(AccessLevel.PROTECTED)
    private static Clock clock = AuthenticationApplication.DEFAULT_CLOCK;

    @Id
    @Column(name = "authorization_code", length = 6)
    private String code;

    @Column(name = "expiration_at", nullable = false)
    private LocalDateTime expirationDateTime;

    @Embedded
    @AttributeOverride(name = "value", column = @Column(name = "client_id", length = 32, nullable = false))
    private OAuth2ClientId clientId;

    @Embedded
    @AttributeOverride(name = "value", column = @Column(name = "email", length = 128, nullable = false))
    private PrincipalUsername username;

    @Column(name = "state", length = 12)
    private String state;

    @Column(name = "redirect_uri", length = 128)
    @Convert(converter = RedirectUriConverter.class)
    private URI redirectURI;

    @ElementCollection
    @CollectionTable(name = "oauth2_code_approved_scope", joinColumns = @JoinColumn(name = "authorization_code", nullable = false))
    @AttributeOverride(name = "value", column = @Column(name = "scope_id", length = 32, nullable = false))
    private Set<OAuth2ScopeId> approvedScopes;

    public OAuth2AuthorizationCode(AuthorizationCodeGenerator generator) {
        this.code = generator.generate();
        this.expirationDateTime = LocalDateTime.now(clock).plusMinutes(5);
    }

    public void setAuthorizationRequest(AuthorizationRequest request) {
        this.clientId = new OAuth2ClientId(request.getClientId());
        this.username = new PrincipalUsername(request.getUsername());
        this.redirectURI = request.getRedirectUri();
        this.approvedScopes = request.getRequestScopes().stream()
                .map(OAuth2ScopeId::new).collect(Collectors.toSet());
    }

    public void validateWithAuthorizationRequest(AuthorizationRequest request) {
        if (expirationDateTime.isBefore(LocalDateTime.now(clock))) {
            throw InvalidGrantException.invalidGrant("Authorization code is expired");
        }

        if ((redirectURI == null && request.getRedirectUri() != null) ||
                (redirectURI != null && !redirectURI.equals(request.getRedirectUri()))) {
            throw new RedirectMismatchException("Redirect URI mismatched");
        }

        if (!clientId.equals(new OAuth2ClientId(request.getClientId()))) {
            throw InvalidClientException.invalidClient("Client id mismatch");
        }
    }
}
