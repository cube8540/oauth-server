package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import lombok.Setter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class ClientCredentialsTokenFactory extends AbstractOAuth2TokenFactory {

    @Setter
    private boolean allowedRefreshToken = false;

    public ClientCredentialsTokenFactory(OAuth2TokenIdGenerator tokenIdGenerator) {
        super(tokenIdGenerator);
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        if (!getTokenRequestValidator().validateScopes(clientDetails, tokenRequest.scopes())) {
            throw new InvalidGrantException("cannot grant scopes");
        }

        OAuth2AuthorizedAccessToken accessToken = OAuth2AuthorizedAccessToken.builder(getTokenIdGenerator())
                .client(new OAuth2ClientId(clientDetails.clientId()))
                .expiration(extractTokenExpiration(clientDetails))
                .tokenGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(extractGrantScope(clientDetails, tokenRequest))
                .build();
        if (allowedRefreshToken) {
            accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails));
        }
        return accessToken;
    }
}
