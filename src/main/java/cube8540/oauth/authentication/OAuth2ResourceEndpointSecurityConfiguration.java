package cube8540.oauth.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetailsService;
import cube8540.oauth.authentication.credentials.oauth.security.introspector.DefaultAccessTokenIntrospector;
import cube8540.oauth.authentication.credentials.security.RoleSecurityConfig;
import cube8540.oauth.authentication.credentials.security.ScopeSecurityConfig;
import cube8540.oauth.authentication.credentials.security.TypeBasedAuthorityVoter;
import cube8540.oauth.authentication.error.DefaultAuthenticationExceptionEntryPoint;
import cube8540.oauth.authentication.error.security.AccessDeniedExceptionResponseRenderer;
import cube8540.oauth.authentication.error.security.AccessDeniedExceptionTranslator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

@Order(3)
@EnableWebSecurity
public class OAuth2ResourceEndpointSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Setter(onMethod_ = @Autowired)
    private Environment environment;

    @Setter(onMethod_ = @Autowired)
    private FilterInvocationSecurityMetadataSource securityMetadataLoadService;

    @Setter(onMethod_ = {@Autowired, @Qualifier("escapeObjectMapper")})
    private ObjectMapper objectMapper;

    @Setter(onMethod_ = {@Autowired, @Qualifier("oAuth2ClientNotCheckedAccessTokenDetailsService")})
    private OAuth2AccessTokenDetailsService accessTokenService;

    private AuthenticationEntryPoint entryPoint;

    @PostConstruct
    public void initialize() throws Exception {
        this.entryPoint = new DefaultAuthenticationExceptionEntryPoint<>(new AccessDeniedExceptionTranslator(),
                new AccessDeniedExceptionResponseRenderer(new MappingJackson2HttpMessageConverter(objectMapper)));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer()
                .opaqueToken(introsptor -> introsptor.introspector(new DefaultAccessTokenIntrospector(accessTokenService)))
                .and()
            .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
                .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
            .addFilterAfter(filterSecurityInterceptor(), FilterSecurityInterceptor.class)
            .csrf().disable()
            .exceptionHandling()
                .defaultAuthenticationEntryPointFor(entryPoint, new AntPathRequestMatcher("/**"));
    }

    @Bean
    public FilterSecurityInterceptor filterSecurityInterceptor() throws Exception {
        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();

        filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
        filterSecurityInterceptor.setSecurityMetadataSource(securityMetadataLoadService);
        filterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());

        return filterSecurityInterceptor;
    }

    private AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<?>> accessDecisionVoters = new ArrayList<>();

        accessDecisionVoters.add(createRoleAuthorityVoter());
        accessDecisionVoters.add(createScopeAuthorityVoter());

        return new UnanimousBased(accessDecisionVoters);
    }

    private RoleVoter createRoleAuthorityVoter() {
        TypeBasedAuthorityVoter roleVoter = new TypeBasedAuthorityVoter(RoleSecurityConfig.class);
        roleVoter.setRolePrefix("");
        return roleVoter;
    }

    private RoleVoter createScopeAuthorityVoter() {
        TypeBasedAuthorityVoter roleVoter = new TypeBasedAuthorityVoter(ScopeSecurityConfig.class);
        roleVoter.setRolePrefix("");
        return roleVoter;
    }
}
