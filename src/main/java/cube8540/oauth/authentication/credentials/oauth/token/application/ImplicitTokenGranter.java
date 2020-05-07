package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.LocalDateTime;

public class ImplicitTokenGranter extends AbstractOAuth2TokenGranter {

    public ImplicitTokenGranter(OAuth2TokenIdGenerator tokenIdGenerator, OAuth2AccessTokenRepository tokenRepository) {
        super(tokenIdGenerator, tokenRepository);
    }

    @Override
    protected OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        return OAuth2AuthorizedAccessToken.builder(getTokenIdGenerator())
                .scopes(extractGrantScope(clientDetails, tokenRequest))
                .username(new UserEmail(tokenRequest.getUsername()))
                .tokenGrantType(AuthorizationGrantType.IMPLICIT)
                .expiration(extractTokenExpiration(clientDetails))
                .client(new OAuth2ClientId(clientDetails.getClientId()))
                .issuedAt(LocalDateTime.now(clock))
                .build();
    }
}
