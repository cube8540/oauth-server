package cube8540.oauth.authentication;

import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;

@Order(2)
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final String DEFAULT_LOGIN_PAGE = "/accounts/signin";
    private static final String DEFAULT_LOGIN_PROCESS_URL = "/accounts/signin";

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
        http.authorizeRequests()
                .antMatchers(HttpMethod.POST,"/api/accounts").permitAll()
                .antMatchers(HttpMethod.GET, "/api/accounts/attributes/email").permitAll()
                .antMatchers(HttpMethod.DELETE, "/api/accounts/attributes/password").permitAll()
                .antMatchers(HttpMethod.POST, "/api/accounts/attributes/password").permitAll()
                .antMatchers(HttpMethod.PUT, "/api/accounts/credentials/**").permitAll()
                .and()
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage(loginPage)
                .loginProcessingUrl(loginProcessUrl)
                .permitAll()
                .and()
            .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**", "/img/**", "/js/**");
    }
}
