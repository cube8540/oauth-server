package cube8540.oauth.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.provider.ClientCredentialsAuthenticationProvider;
import cube8540.oauth.authentication.credentials.oauth.client.provider.ClientCredentialsEndpointFilter;
import cube8540.oauth.authentication.credentials.oauth.code.application.OAuth2AuthorizationCodeService;
import cube8540.oauth.authentication.credentials.oauth.error.DefaultOAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.error.DefaultOauth2ExceptionResponseRenderer;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2AuthenticationExceptionEntryPoint;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionResponseRenderer;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.infra.AuthorizationCodeTokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.infra.ClientCredentialsTokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.infra.DefaultTokenIdGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.infra.OAuth2AccessTokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.infra.RefreshTokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.infra.ResourceOwnerPasswordTokenFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private UserDetailsService userDetailsService;
    private OAuth2ClientDetailsService clientDetailsService;
    private OAuth2AuthorizationCodeService authorizationCodeService;
    private OAuth2RefreshTokenRepository refreshTokenRepository;

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder()).and()
                .authenticationProvider(new ClientCredentialsAuthenticationProvider(clientDetailsService, passwordEncoder()));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin().and()
                .httpBasic().disable()
                .csrf().disable()
                .addFilterBefore(clientCredentialsEndpointFilter(), BasicAuthenticationFilter.class);
    }

    @Bean
    public ClientCredentialsEndpointFilter clientCredentialsEndpointFilter() throws Exception {
        ObjectMapper mapper = new ObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
        MappingJackson2HttpMessageConverter messageConverter = new MappingJackson2HttpMessageConverter(mapper);

        OAuth2ExceptionTranslator translator = new DefaultOAuth2ExceptionTranslator();
        OAuth2ExceptionResponseRenderer renderer = new DefaultOauth2ExceptionResponseRenderer(messageConverter);

        ClientCredentialsEndpointFilter filter = new ClientCredentialsEndpointFilter("/oauth/token");
        filter.setEntryPoint(new OAuth2AuthenticationExceptionEntryPoint(translator, renderer));
        filter.setAuthenticationManager(authenticationManagerBean());
        return filter;
    }

    @Bean
    public OAuth2TokenFactory accessTokenFactory() throws Exception {
        OAuth2AccessTokenFactory tokenFactory = new OAuth2AccessTokenFactory();

        tokenFactory.putTokenFactoryMap(AuthorizationGrantType.AUTHORIZATION_CODE,
                new AuthorizationCodeTokenFactory(tokenIdGenerator(), authorizationCodeService));
        tokenFactory.putTokenFactoryMap(AuthorizationGrantType.REFRESH_TOKEN,
                new RefreshTokenFactory(refreshTokenRepository, tokenIdGenerator()));
        tokenFactory.putTokenFactoryMap(AuthorizationGrantType.CLIENT_CREDENTIALS,
                new ClientCredentialsTokenFactory(tokenIdGenerator()));
        tokenFactory.putTokenFactoryMap(AuthorizationGrantType.PASSWORD,
                new ResourceOwnerPasswordTokenFactory(tokenIdGenerator(), authenticationManagerBean()));
        return tokenFactory;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OAuth2TokenIdGenerator tokenIdGenerator() {
        return new DefaultTokenIdGenerator();
    }

    @Autowired
    @Qualifier("defaultUserService")
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Autowired
    public void setClientDetailsService(OAuth2ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    @Autowired
    public void setAuthorizationCodeService(OAuth2AuthorizationCodeService authorizationCodeService) {
        this.authorizationCodeService = authorizationCodeService;
    }

    @Autowired
    public void setRefreshTokenRepository(OAuth2RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }
}
