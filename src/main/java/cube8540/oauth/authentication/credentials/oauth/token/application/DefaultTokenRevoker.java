package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRevoker;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.exception.TokenNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DefaultTokenRevoker implements OAuth2TokenRevoker {

    private final OAuth2AccessTokenRepository repository;

    @Autowired
    public DefaultTokenRevoker(OAuth2AccessTokenRepository repository) {
        this.repository = repository;
    }

    @Override
    public OAuth2AccessTokenDetails revoke(String tokenValue) {
        OAuth2AuthorizedAccessToken token = repository.findById(new OAuth2TokenId(tokenValue))
                .orElseThrow(() -> TokenNotFoundException.instance(tokenValue + " is not found"));
        repository.delete(token);
        return DefaultAccessTokenDetails.of(token);
    }
}
