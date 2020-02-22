package cube8540.oauth.authentication.credentials.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.provider.ClientCredentialsAuthenticationProvider;
import cube8540.oauth.authentication.credentials.oauth.client.provider.ClientCredentialsEndpointFilter;
import cube8540.oauth.authentication.credentials.oauth.error.DefaultOauth2ExceptionResponseRenderer;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2AuthenticationExceptionEntryPoint;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionResponseRenderer;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.token.application.AuthorizationCodeTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.application.ClientCredentialsTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.application.CompositeOAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AccessTokenGrantService;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AuthorizationCodeConsumer;
import cube8540.oauth.authentication.credentials.oauth.token.application.RefreshTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.application.ResourceOwnerPasswordTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.infra.DefaultTokenIdGenerator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.web.HttpMediaTypeNotSupportedException;

@Order(1)
@EnableWebSecurity
public class OAuth2EndpointSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultOAuth2ClientDetailsService")})
    private OAuth2ClientDetailsService clientDetailsService;

    @Setter(onMethod_ = @Autowired)
    private OAuth2AuthorizationCodeConsumer authorizationCodeConsumer;

    @Setter(onMethod_ = @Autowired)
    private OAuth2AccessTokenRepository accessTokenRepository;

    @Setter(onMethod_ = @Autowired)
    private OAuth2RefreshTokenRepository refreshTokenRepository;

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultUserService")})
    private UserDetailsService userDetailsService;

    @Setter(onMethod_= @Autowired)
    private PasswordEncoder passwordEncoder;

    @Setter
    private OAuth2AuthenticationExceptionEntryPoint oAuth2AuthenticationExceptionEntryPoint;

    public OAuth2EndpointSecurityConfiguration() throws HttpMediaTypeNotSupportedException {
        ObjectMapper objectMapper = new ObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
        MappingJackson2HttpMessageConverter messageConverter = new MappingJackson2HttpMessageConverter(objectMapper);
        OAuth2ExceptionTranslator translator = new OAuth2ExceptionTranslator();
        OAuth2ExceptionResponseRenderer renderer = new DefaultOauth2ExceptionResponseRenderer(messageConverter);

        this.oAuth2AuthenticationExceptionEntryPoint = new OAuth2AuthenticationExceptionEntryPoint(translator, renderer);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder).and()
                .authenticationProvider(new ClientCredentialsAuthenticationProvider(clientDetailsService, passwordEncoder));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
                .antMatchers("/oauth/token", "/oauth/token_info", "/oauth/user_info")
                .and()
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .addFilterBefore(tokenEndpointClientCredentialsFilter(), UsernamePasswordAuthenticationFilter.class)
            .securityContext()
                .securityContextRepository(new NullSecurityContextRepository())
                .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
            .csrf().disable();
    }

    @Bean
    public ClientCredentialsEndpointFilter tokenEndpointClientCredentialsFilter() throws Exception {
        ClientCredentialsEndpointFilter filter = new ClientCredentialsEndpointFilter("/oauth/**");
        filter.setEntryPoint(oAuth2AuthenticationExceptionEntryPoint);
        filter.setAuthenticationManager(authenticationManagerBean());
        return filter;
    }

    @Bean
    public OAuth2AccessTokenGrantService accessTokenGranter() throws Exception {
        CompositeOAuth2AccessTokenGranter tokenGranter = new CompositeOAuth2AccessTokenGranter();

        tokenGranter.putTokenGranterMap(AuthorizationGrantType.AUTHORIZATION_CODE,
                new AuthorizationCodeTokenGranter(tokenIdGenerator(), accessTokenRepository, authorizationCodeConsumer));
        tokenGranter.putTokenGranterMap(AuthorizationGrantType.REFRESH_TOKEN,
                new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, tokenIdGenerator()));
        tokenGranter.putTokenGranterMap(AuthorizationGrantType.CLIENT_CREDENTIALS,
                new ClientCredentialsTokenGranter(tokenIdGenerator(), accessTokenRepository));
        tokenGranter.putTokenGranterMap(AuthorizationGrantType.PASSWORD,
                new ResourceOwnerPasswordTokenGranter(tokenIdGenerator(), accessTokenRepository, authenticationManagerBean()));
        return tokenGranter;
    }

    @Bean
    public OAuth2TokenIdGenerator tokenIdGenerator() {
        return new DefaultTokenIdGenerator();
    }
}
