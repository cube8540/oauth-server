package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DefaultOAuth2TokenRevokeService implements OAuth2TokenRevokeService {

    private final OAuth2AccessTokenRepository repository;

    @Autowired
    public DefaultOAuth2TokenRevokeService(OAuth2AccessTokenRepository repository) {
        this.repository = repository;
    }

    @Override
    public OAuth2AccessTokenDetails revoke(String tokenValue) {
        OAuth2AuthorizedAccessToken accessToken = repository.findById(new OAuth2TokenId(tokenValue))
                .orElseThrow(() -> new OAuth2AccessTokenNotFoundException(tokenValue + " is not found"));

        repository.delete(accessToken);
        return DefaultAccessTokenDetails.of(accessToken);
    }
}
