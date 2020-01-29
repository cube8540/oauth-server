package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequestValidator;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class AbstractOAuth2TokenFactory implements OAuth2TokenFactory {

    @Getter(AccessLevel.PROTECTED)
    private final OAuth2TokenIdGenerator tokenIdGenerator;

    @Getter(AccessLevel.PROTECTED)
    @Setter(AccessLevel.PUBLIC)
    private OAuth2TokenIdGenerator refreshTokenIdGenerator;

    @Getter(AccessLevel.PROTECTED)
    @Setter(AccessLevel.PUBLIC)
    private OAuth2TokenRequestValidator tokenRequestValidator;

    protected AbstractOAuth2TokenFactory(OAuth2TokenIdGenerator tokenIdGenerator) {
        this.tokenIdGenerator = tokenIdGenerator;
    }

    protected LocalDateTime extractTokenExpiration(OAuth2ClientDetails clientDetails) {
        return LocalDateTime.now().plusSeconds(clientDetails.accessTokenValiditySeconds());
    }

    protected LocalDateTime extractRefreshTokenExpiration(OAuth2ClientDetails clientDetails) {
        return LocalDateTime.now().plusSeconds(clientDetails.refreshTokenValiditySeconds());
    }

    protected OAuth2TokenIdGenerator refreshTokenGenerator() {
        return refreshTokenIdGenerator != null ? refreshTokenIdGenerator : tokenIdGenerator;
    }

    protected Set<OAuth2ScopeId> extractGrantScope(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        return (tokenRequest.scopes() == null || tokenRequest.scopes().isEmpty() ? clientDetails.scope() : tokenRequest.scopes())
                .stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());
    }
}
