package cube8540.oauth.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

@Order(2)
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final String DEFAULT_LOGIN_PAGE = "/accounts/signin";
    private static final String DEFAULT_LOGIN_PROCESS_URL = "/accounts/signin";
    private static final String DEFAULT_LOGOUT_URL = "/accounts/signout";

    @Setter(onMethod_ = @Autowired)
    private Environment environment;

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultUserService")})
    private UserDetailsService userDetailsService;

    @Setter(onMethod_ = @Autowired)
    private PasswordEncoder passwordEncoder;

    @Setter(onMethod_ = @Autowired)
    private FilterInvocationSecurityMetadataSource securityMetadataLoadService;

    @Setter(onMethod_ = {@Autowired, @Qualifier("escapeObjectMapper")})
    private ObjectMapper objectMapper;

    private AuthenticationEntryPoint entryPoint;

    @PostConstruct
    public void initialize() throws Exception {
        this.entryPoint = new DefaultAuthenticationExceptionEntryPoint<>(new AccessDeniedExceptionTranslator(),
                new AccessDeniedExceptionResponseRenderer(new MappingJackson2HttpMessageConverter(objectMapper)));
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    @Bean(name = "webSecurityAuthentication")
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage(DEFAULT_LOGIN_PAGE)
                .loginProcessingUrl(DEFAULT_LOGIN_PROCESS_URL)
                .defaultSuccessUrl(environment.getProperty("front.endpoint.login-success-page"))
                .permitAll()
                .and()
            .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
                .and()
            .logout()
                .logoutUrl(DEFAULT_LOGOUT_URL)
                .logoutSuccessUrl(environment.getProperty("front.endpoint.logout-success-page"))
                .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .and()
            .addFilterAfter(filterSecurityInterceptor(), FilterSecurityInterceptor.class)
            .exceptionHandling()
                .defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint(DEFAULT_LOGIN_PAGE), new AntPathRequestMatcher("/oauth/authorize"))
                .defaultAuthenticationEntryPointFor(entryPoint, new AntPathRequestMatcher("/**"));
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**", "/img/**", "/js/**");
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

        accessDecisionVoters.add(createWebExpressionVoter());
        accessDecisionVoters.add(createRoleVoter());

        return new AffirmativeBased(accessDecisionVoters);
    }

    private WebExpressionVoter createWebExpressionVoter() {
        WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
        DefaultWebSecurityExpressionHandler webSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();

        webSecurityExpressionHandler.setDefaultRolePrefix("");
        webExpressionVoter.setExpressionHandler(webSecurityExpressionHandler);

        return webExpressionVoter;
    }

    private RoleVoter createRoleVoter() {
        RoleVoter roleVoter = new RoleVoter();
        roleVoter.setRolePrefix("");
        return roleVoter;
    }
}
