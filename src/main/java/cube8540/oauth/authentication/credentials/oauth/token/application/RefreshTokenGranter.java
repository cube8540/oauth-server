package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;

public class RefreshTokenGranter extends AbstractOAuth2TokenGranter {

    private final OAuth2RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenGranter(OAuth2AccessTokenRepository tokenRepository, OAuth2RefreshTokenRepository refreshTokenRepository,
                               OAuth2TokenIdGenerator tokenIdGenerator) {
        super(tokenIdGenerator, tokenRepository);
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        if (!getTokenRequestValidator().validateScopes(clientDetails, tokenRequest.scopes())) {
            throw new InvalidGrantException("cannot grant scopes");
        }
        OAuth2AuthorizedRefreshToken storedRefreshToken = refreshTokenRepository.findById(new OAuth2TokenId(tokenRequest.refreshToken()))
                .orElseThrow(() -> new InvalidGrantException("invalid refresh token"));
        OAuth2AuthorizedAccessToken storedAccessToken = storedRefreshToken.getAccessToken();
        if (!storedAccessToken.getClient().equals(new OAuth2ClientId(clientDetails.clientId()))) {
            throw new InvalidGrantException("invalid refresh token");
        }
        refreshTokenRepository.delete(storedRefreshToken);
        if (storedRefreshToken.isExpired()) {
            throw new InvalidGrantException("refresh token is expired");
        }
        OAuth2AuthorizedAccessToken accessToken = OAuth2AuthorizedAccessToken.builder(getTokenIdGenerator())
                .expiration(extractTokenExpiration(clientDetails))
                .client(storedAccessToken.getClient())
                .email(storedAccessToken.getEmail())
                .scope(extractGrantScope(clientDetails, tokenRequest))
                .tokenGrantType(storedAccessToken.getTokenGrantType())
                .build();
        accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails));

        return accessToken;
    }
}
