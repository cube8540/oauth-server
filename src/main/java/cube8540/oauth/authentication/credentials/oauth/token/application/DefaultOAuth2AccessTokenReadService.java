package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.DefaultAccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenExpiredException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DefaultOAuth2AccessTokenReadService implements OAuth2AccessTokenReadService {

    private final OAuth2AccessTokenRepository tokenRepository;

    @Autowired
    public DefaultOAuth2AccessTokenReadService(OAuth2AccessTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
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
}
