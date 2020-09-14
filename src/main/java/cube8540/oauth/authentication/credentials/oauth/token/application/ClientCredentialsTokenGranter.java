package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class ClientCredentialsTokenGranter extends AbstractOAuth2TokenGranter {

    @Setter
    private boolean allowedRefreshToken = false;

    public ClientCredentialsTokenGranter(@Qualifier("defaultTokenIdGenerator") OAuth2TokenIdGenerator tokenIdGenerator,
                                         OAuth2AccessTokenRepository tokenRepository) {
        super(tokenIdGenerator, tokenRepository);
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        if (!getTokenRequestValidator().validateScopes(clientDetails, tokenRequest.getScopes())) {
            throw InvalidGrantException.invalidScope("cannot grant scopes");
        }

        OAuth2AuthorizedAccessToken accessToken = OAuth2AuthorizedAccessToken.builder(getTokenIdGenerator())
                .client(new OAuth2ClientId(clientDetails.getClientId()))
                .expiration(extractTokenExpiration(clientDetails))
                .tokenGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(extractGrantScope(clientDetails, tokenRequest))
                .issuedAt(LocalDateTime.now(clock))
                .build();
        if (allowedRefreshToken) {
            accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails));
        }
        accessToken.generateComposeUniqueKey(getComposeUniqueKeyGenerator());
        return accessToken;
    }
}
