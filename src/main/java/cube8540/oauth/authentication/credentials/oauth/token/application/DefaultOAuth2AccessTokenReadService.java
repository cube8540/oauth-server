package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenExpiredException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class DefaultOAuth2AccessTokenReadService implements OAuth2AccessTokenReadService {

    private final OAuth2AccessTokenRepository tokenRepository;
    private final UserDetailsService userDetailsService;

    @Autowired
    public DefaultOAuth2AccessTokenReadService(OAuth2AccessTokenRepository tokenRepository,
                                               @Qualifier("defaultUserService") UserDetailsService userDetailsService) {
        this.tokenRepository = tokenRepository;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public OAuth2AccessTokenDetails readAccessToken(String tokenValue) {
        OAuth2AuthorizedAccessToken accessToken = tokenRepository.findById(new OAuth2TokenId(tokenValue))
                .orElseThrow(() -> new OAuth2AccessTokenNotFoundException("[" + tokenValue + "] token is not found"));
        if (accessToken.isExpired()) {
            throw new OAuth2AccessTokenExpiredException("[" + tokenValue + "] is expired");
        }
        assertTokenClient(accessToken);
        return DefaultAccessTokenDetails.of(accessToken);
    }

    @Override
    public UserDetails readAccessTokenUser(String tokenValue) {
        OAuth2AuthorizedAccessToken accessToken = tokenRepository.findById(new OAuth2TokenId(tokenValue))
                .orElseThrow(() -> new OAuth2AccessTokenNotFoundException("[" + tokenValue + "] token is not found"));

        assertTokenClient(accessToken);
        UserDetails user = userDetailsService.loadUserByUsername(accessToken.getUsername().getValue());
        if (user instanceof CredentialsContainer) {
            ((CredentialsContainer) user).eraseCredentials();
        }
        return user;
    }

    private void assertTokenClient(OAuth2AuthorizedAccessToken accessToken) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!authentication.getName().equals(accessToken.getClient().getValue())) {
            throw InvalidClientException.invalidClient("client and access token client is different");
        }
    }
}
