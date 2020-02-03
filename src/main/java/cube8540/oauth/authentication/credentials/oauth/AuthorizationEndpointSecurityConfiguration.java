package cube8540.oauth.authentication.credentials.oauth;

import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Order(2)
@EnableWebSecurity
public class AuthorizationEndpointSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final String DEFAULT_LOGIN_PAGE = "/login";
    private static final String DEFAULT_LOGIN_PROCESS_URL = "/login";

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultUserService")})
    private UserDetailsService userDetailsService;

    @Setter(onMethod_ = @Autowired)
    private PasswordEncoder passwordEncoder;

    @Setter
    private String loginPage = DEFAULT_LOGIN_PAGE;

    @Setter
    private String loginProcessUrl = DEFAULT_LOGIN_PROCESS_URL;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
                .antMatchers("/oauth/authorize")
                .antMatchers(HttpMethod.GET, loginPage)
                .antMatchers(HttpMethod.POST, loginProcessUrl)
                .and()
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .permitAll();
    }
}
