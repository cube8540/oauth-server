package cube8540.oauth.authentication.credentials.oauth.token;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.application.AuthorizationCodeTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.application.ClientCredentialsTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.application.CompositeOAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AuthorizationCodeConsumer;
import cube8540.oauth.authentication.credentials.oauth.token.application.RefreshTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.application.ResourceOwnerPasswordTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.infra.DefaultTokenIdGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.infra.TokenExceptionTranslator;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@Configuration
public class TokenConfiguration {

    @Setter(onMethod_ = @Autowired)
    private OAuth2AuthorizationCodeConsumer authorizationCodeConsumer;

    @Setter(onMethod_ = @Autowired)
    private OAuth2AccessTokenRepository accessTokenRepository;

    @Setter(onMethod_ = @Autowired)
    private OAuth2RefreshTokenRepository refreshTokenRepository;

    @Setter(onMethod_ = {@Autowired, @Qualifier("oauthAuthenticationBean")})
    private AuthenticationManager authenticationManager;

    @Bean
    public OAuth2AccessTokenGranter accessTokenGranter() {
        CompositeOAuth2AccessTokenGranter tokenGranter = new CompositeOAuth2AccessTokenGranter();

        tokenGranter.putTokenGranterMap(AuthorizationGrantType.AUTHORIZATION_CODE,
                new AuthorizationCodeTokenGranter(tokenIdGenerator(), accessTokenRepository, authorizationCodeConsumer));
        tokenGranter.putTokenGranterMap(AuthorizationGrantType.REFRESH_TOKEN,
                new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, tokenIdGenerator()));
        tokenGranter.putTokenGranterMap(AuthorizationGrantType.CLIENT_CREDENTIALS,
                new ClientCredentialsTokenGranter(tokenIdGenerator(), accessTokenRepository));
        tokenGranter.putTokenGranterMap(AuthorizationGrantType.PASSWORD,
                new ResourceOwnerPasswordTokenGranter(tokenIdGenerator(), accessTokenRepository, authenticationManager));
        return tokenGranter;
    }

    @Bean
    public OAuth2TokenIdGenerator tokenIdGenerator() {
        return new DefaultTokenIdGenerator();
    }

    @Bean
    public ExceptionTranslator<ErrorMessage<Object>> tokenExceptionTranslator() {
        return new TokenExceptionTranslator();
    }

}
