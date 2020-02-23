package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;

import java.util.Set;
import java.util.stream.Collectors;

public class RefreshTokenGranter extends AbstractOAuth2TokenGranter {

    private final OAuth2RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenGranter(OAuth2AccessTokenRepository tokenRepository, OAuth2RefreshTokenRepository refreshTokenRepository,
                               OAuth2TokenIdGenerator tokenIdGenerator) {
        super(tokenIdGenerator, tokenRepository);
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        OAuth2AuthorizedRefreshToken storedRefreshToken = refreshTokenRepository.findById(new OAuth2TokenId(tokenRequest.getRefreshToken()))
                .orElseThrow(() -> InvalidGrantException.invalidGrant("invalid refresh token"));
        OAuth2AuthorizedAccessToken storedAccessToken = storedRefreshToken.getAccessToken();
        if (!storedAccessToken.getClient().equals(new OAuth2ClientId(clientDetails.getClientId()))) {
            throw InvalidClientException.invalidClient("invalid refresh token");
        }

        refreshTokenRepository.delete(storedRefreshToken);
        if (storedRefreshToken.isExpired()) {
            throw InvalidGrantException.invalidGrant("refresh token is expired");
        }

        Set<String> storedAccessTokenScopes = storedAccessToken.getScopes().stream().map(OAuth2ScopeId::getValue).collect(Collectors.toSet());
        if (!getTokenRequestValidator().validateScopes(storedAccessTokenScopes, tokenRequest.getScopes())) {
            throw InvalidGrantException.invalidScope("cannot grant scope");
        }
        OAuth2AuthorizedAccessToken accessToken = OAuth2AuthorizedAccessToken.builder(getTokenIdGenerator())
                .expiration(extractTokenExpiration(clientDetails))
                .client(storedAccessToken.getClient())
                .username(storedAccessToken.getUsername())
                .scopes(extractGrantScope(storedAccessToken, tokenRequest))
                .tokenGrantType(storedAccessToken.getTokenGrantType())
                .build();
        accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails));

        return accessToken;
    }

    protected Set<OAuth2ScopeId> extractGrantScope(OAuth2AuthorizedAccessToken accessToken, OAuth2TokenRequest tokenRequest) {
        return (tokenRequest.getScopes() == null || tokenRequest.getScopes().isEmpty()) ? accessToken.getScopes() :
                tokenRequest.getScopes().stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());
    }
}
