package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2TokenRequestValidator;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

public class ClientCredentialsTokenFactory implements OAuth2TokenFactory {

    private final OAuth2TokenIdGenerator tokenIdGenerator;

    private boolean allowedRefreshToken = false;
    private OAuth2TokenIdGenerator refreshTokenIdGenerator;

    private OAuth2TokenRequestValidator validator = new DefaultOAuth2TokenRequestValidator();

    public ClientCredentialsTokenFactory(OAuth2TokenIdGenerator tokenIdGenerator) {
        this.tokenIdGenerator = tokenIdGenerator;
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        if (!validator.validateScopes(clientDetails, tokenRequest)) {
            throw new InvalidGrantException("cannot grant scopes");
        }

        OAuth2AuthorizedAccessToken accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                .client(new OAuth2ClientId(clientDetails.clientId()))
                .expiration(extractExpirationDateTime(clientDetails))
                .tokenGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(extractGrantedScopes(clientDetails, tokenRequest))
                .build();
        if (allowedRefreshToken) {
            accessToken.generateRefreshToken(extractTokenIdGenerator(), extractRefreshTokenExpirationDateTime(clientDetails));
        }
        return accessToken;
    }

    private OAuth2TokenIdGenerator extractTokenIdGenerator() {
        return refreshTokenIdGenerator != null ? refreshTokenIdGenerator : tokenIdGenerator;
    }

    private Set<OAuth2ScopeId> extractGrantedScopes(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        return (tokenRequest.scopes() == null || tokenRequest.scopes().isEmpty() ? clientDetails.scope() : tokenRequest.scopes())
                .stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());
    }

    private LocalDateTime extractExpirationDateTime(OAuth2ClientDetails clientDetails) {
        return LocalDateTime.now().plusSeconds(clientDetails.accessTokenValiditySeconds());
    }

    private LocalDateTime extractRefreshTokenExpirationDateTime(OAuth2ClientDetails clientDetails) {
        return LocalDateTime.now().plusSeconds(clientDetails.refreshTokenValiditySeconds());
    }

    public void setValidator(OAuth2TokenRequestValidator validator) {
        this.validator = validator;
    }

    public void setAllowedRefreshToken(boolean allowedRefreshToken) {
        this.allowedRefreshToken = allowedRefreshToken;
    }

    public void setRefreshTokenIdGenerator(OAuth2TokenIdGenerator refreshTokenIdGenerator) {
        this.refreshTokenIdGenerator = refreshTokenIdGenerator;
    }
}
