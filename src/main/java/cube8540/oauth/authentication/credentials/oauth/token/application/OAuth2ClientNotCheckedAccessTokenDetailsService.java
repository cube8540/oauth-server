package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetailsService;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service(value = "oAuth2ClientNotCheckedAccessTokenDetailsService")
public class OAuth2ClientNotCheckedAccessTokenDetailsService implements OAuth2AccessTokenDetailsService {

    private final OAuth2AccessTokenRepository tokenRepository;
    private final UserDetailsService userDetailsService;

    @Autowired
    public OAuth2ClientNotCheckedAccessTokenDetailsService(OAuth2AccessTokenRepository tokenRepository,
                                                           @Qualifier("defaultUserService") UserDetailsService userDetailsService) {
        this.tokenRepository = tokenRepository;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public OAuth2AccessTokenDetails readAccessToken(String tokenValue) {
        OAuth2AuthorizedAccessToken accessToken = tokenRepository.findById(new OAuth2TokenId(tokenValue))
                .orElseThrow(() -> new OAuth2AccessTokenNotFoundException(tokenValue));
        return DefaultAccessTokenDetails.of(accessToken);
    }

    @Override
    public UserDetails readAccessTokenUser(String tokenValue) {
        OAuth2AuthorizedAccessToken accessToken = tokenRepository.findById(new OAuth2TokenId(tokenValue))
                .orElseThrow(() -> new OAuth2AccessTokenNotFoundException(tokenValue));

        UserDetails user = userDetailsService.loadUserByUsername(accessToken.getUsername().getValue());
        if (user instanceof CredentialsContainer) {
            ((CredentialsContainer) user).eraseCredentials();
        }
        return user;
    }
}
