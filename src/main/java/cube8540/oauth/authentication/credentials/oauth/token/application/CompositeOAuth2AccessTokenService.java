package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.token.DefaultAccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenGrantService;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenExpiredException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenEnhancer;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CompositeOAuth2AccessTokenService implements OAuth2AccessTokenGrantService, OAuth2AccessTokenService {

    private final OAuth2AccessTokenRepository tokenRepository;
    private final OAuth2TokenFactory tokenFactory;

    @Setter
    private OAuth2TokenEnhancer enhancer = new NullOAuth2TokenEnhancer();

    @Autowired
    public CompositeOAuth2AccessTokenService(OAuth2AccessTokenRepository tokenRepository, OAuth2TokenFactory tokenFactory) {
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

    @Override
    public OAuth2AccessTokenDetails readAccessToken(String tokenValue) {
        OAuth2AuthorizedAccessToken accessToken = tokenRepository.findById(new OAuth2TokenId(tokenValue))
                .orElseThrow(() -> new OAuth2AccessTokenNotFoundException("[" + tokenValue + "] token is not found"));

        if (accessToken.isExpired()) {
            throw new OAuth2AccessTokenExpiredException("[" + tokenValue + "] is expired");
        }
        return new DefaultAccessTokenDetails(accessToken);
    }

    private static final class NullOAuth2TokenEnhancer implements OAuth2TokenEnhancer {

        @Override
        public void enhance(OAuth2AuthorizedAccessToken accessToken) {
        }
    }
}
