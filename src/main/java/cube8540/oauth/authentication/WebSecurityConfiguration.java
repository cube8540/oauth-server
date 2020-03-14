package cube8540.oauth.authentication;

import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.web.cors.CorsConfiguration;

import java.util.ArrayList;
import java.util.List;

@Order(2)
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final String DEFAULT_LOGIN_PAGE = "/accounts/signin";
    private static final String DEFAULT_LOGIN_PROCESS_URL = "/accounts/signin";

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultUserService")})
    private UserDetailsService userDetailsService;

    @Setter(onMethod_ = @Autowired)
    private PasswordEncoder passwordEncoder;

    @Setter(onMethod_ = @Autowired)
    private FilterInvocationSecurityMetadataSource securityMetadataLoadService;

    @Setter
    private String loginPage = DEFAULT_LOGIN_PAGE;

    @Setter
    private String loginProcessUrl = DEFAULT_LOGIN_PROCESS_URL;

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
                .loginPage(loginPage)
                .loginProcessingUrl(loginProcessUrl)
                .permitAll()
                .and()
            .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
                .and()
            .addFilterAfter(filterSecurityInterceptor(), FilterSecurityInterceptor.class);
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

        RoleVoter roleVoter = new RoleVoter();
        roleVoter.setRolePrefix("");

        accessDecisionVoters.add(roleVoter);

        return new UnanimousBased(accessDecisionVoters);
    }
}
