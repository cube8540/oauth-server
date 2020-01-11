package cube8540.oauth.authentication.credentials.oauth.code.domain;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuth2AuthorizationCode extends AbstractAggregateRoot<OAuth2AuthorizationCode> {

    private AuthorizationCode code;

    private LocalDateTime expirationDateTime;

    private OAuth2ClientId clientId;

    private UserEmail email;

    private String state;

    private URI redirectURI;

    private Set<OAuth2ScopeId> approvedScopes;

    public OAuth2AuthorizationCode(AuthorizationCodeGenerator generator, LocalDateTime expirationDateTime) {
        this.code = generator.generate();
        this.expirationDateTime = expirationDateTime;
    }

    public void setAuthorizationRequest(AuthorizationRequest request) {
        this.clientId = new OAuth2ClientId(request.clientId());
        this.email = new UserEmail(request.email());
        this.state = request.state();
        this.redirectURI = request.redirectURI();
        this.approvedScopes = request.approvedScopes().stream()
                .map(OAuth2ScopeId::new).collect(Collectors.toSet());
    }

    public void validateWithAuthorizationRequest(AuthorizationRequest request) {
        if (expirationDateTime.isBefore(LocalDateTime.now())) {
            throw new AuthorizationCodeExpiredException("authorization code is expired");
        }

        if (!redirectURI.equals(request.redirectURI())) {
            throw new RedirectMismatchException("Redirect URI mismatched");
        }

        if (!clientId.equals(new OAuth2ClientId(request.clientId()))) {
            throw new InvalidClientException("client id mismatch");
        }
    }
}
