package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenGrantService;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenEnhancer;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
import lombok.Setter;

public class DefaultOAuth2AccessTokenGrantService implements OAuth2AccessTokenGrantService {

    private final OAuth2AccessTokenRepository tokenRepository;
    private final OAuth2TokenFactory tokenFactory;

    @Setter
    private OAuth2TokenEnhancer enhancer = new NullOAuth2TokenEnhancer();

    public DefaultOAuth2AccessTokenGrantService(OAuth2AccessTokenRepository tokenRepository, OAuth2TokenFactory tokenFactory) {
        this.tokenRepository = tokenRepository;
        this.tokenFactory = tokenFactory;
    }

    @Override
    public OAuth2AccessTokenDetails grant(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        OAuth2AuthorizedAccessToken accessToken = tokenFactory.createAccessToken(clientDetails, tokenRequest);
        tokenRepository.findByClientAndEmail(accessToken.getClient(), accessToken.getEmail())
                .ifPresent(tokenRepository::delete);
        enhancer.enhance(accessToken);
        tokenRepository.save(accessToken);
        return new DefaultAccessTokenDetails(accessToken);
    }

    private static final class NullOAuth2TokenEnhancer implements OAuth2TokenEnhancer {

        @Override
        public void enhance(OAuth2AuthorizedAccessToken accessToken) {
        }
    }
}
