package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRevoker;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.exception.TokenAccessDeniedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class UserAuthenticationBaseTokenRevoker implements OAuth2TokenRevoker {

    private final OAuth2AccessTokenRepository repository;

    @Autowired
    public UserAuthenticationBaseTokenRevoker(OAuth2AccessTokenRepository repository) {
        this.repository = repository;
    }

    @Override
    public OAuth2AccessTokenDetails revoke(String tokenValue) {
        OAuth2AuthorizedAccessToken token = repository.findById(new OAuth2TokenId(tokenValue))
                .orElseThrow(() -> new OAuth2AccessTokenNotFoundException(tokenValue));
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!authentication.getName().equals(token.getUsername().getValue())) {
            throw TokenAccessDeniedException.denied("user and access token user is different");
        }
        repository.delete(token);
        return DefaultAccessTokenDetails.of(token);
    }
}
