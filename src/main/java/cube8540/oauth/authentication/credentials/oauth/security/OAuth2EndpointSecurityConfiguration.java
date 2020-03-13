package cube8540.oauth.authentication.credentials.oauth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import cube8540.oauth.authentication.credentials.oauth.error.DefaultOauth2ExceptionResponseRenderer;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2AuthenticationExceptionEntryPoint;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionResponseRenderer;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsAuthenticationProvider;
import cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsEndpointFilter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;

import javax.annotation.PostConstruct;

@Order(1)
@EnableWebSecurity
public class OAuth2EndpointSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultOAuth2ClientDetailsService")})
    private OAuth2ClientDetailsService clientDetailsService;

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultUserService")})
    private UserDetailsService userDetailsService;

    @Setter(onMethod_= @Autowired)
    private PasswordEncoder passwordEncoder;

    @Setter(onMethod_ = {@Autowired, @Qualifier("escapeObjectMapper")})
    private ObjectMapper objectMapper;

    @Setter
    private OAuth2AuthenticationExceptionEntryPoint oAuth2AuthenticationExceptionEntryPoint;

    @PostConstruct
    public void initialize() throws Exception {
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
    @Bean(name = "oauthAuthenticationBean")
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
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
            .csrf().disable()
            .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues());
    }

    @Bean
    public ClientCredentialsEndpointFilter tokenEndpointClientCredentialsFilter() throws Exception {
        ClientCredentialsEndpointFilter filter = new ClientCredentialsEndpointFilter("/oauth/**");
        filter.setEntryPoint(oAuth2AuthenticationExceptionEntryPoint);
        filter.setAuthenticationManager(authenticationManagerBean());
        return filter;
    }
}
