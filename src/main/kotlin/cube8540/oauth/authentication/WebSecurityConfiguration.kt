package cube8540.oauth.authentication

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.core.annotation.Order
import org.springframework.core.env.Environment
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.web.cors.CorsConfiguration

@Order(2)
@EnableWebSecurity
class WebSecurityConfiguration: WebSecurityConfigurerAdapter() {

    companion object {
        private const val DEFAULT_LOGIN_PAGE = "/accounts/signin"
        private const val DEFAULT_LOGIN_PROCESS_URL = "/accounts/signin"
        private const val DEFAULT_LOGOUT_URL = "/accounts/signout"
    }

    @set:[Autowired]
    lateinit var environment: Environment

    @set:[Autowired Qualifier("defaultUserService")]
    lateinit var userDetailsService: UserDetailsService

    @set:[Autowired]
    lateinit var passwordEncoder: PasswordEncoder

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder)
    }

    @Bean(name = ["webSecurityAuthentication"])
    override fun authenticationManagerBean(): AuthenticationManager = super.authenticationManagerBean()

    override fun configure(http: HttpSecurity) {
        http.requestMatchers()
                .antMatchers("/oauth/authorize", DEFAULT_LOGIN_PAGE, DEFAULT_LOGIN_PROCESS_URL, DEFAULT_LOGOUT_URL)
                .and()
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage(DEFAULT_LOGIN_PAGE)
                .loginProcessingUrl(DEFAULT_LOGIN_PROCESS_URL)
                .defaultSuccessUrl(environment.getProperty("front.endpoint.login-success-page"))
                .permitAll()
                .and()
            .cors()
                .configurationSource { CorsConfiguration().applyPermitDefaultValues() }
                .and()
            .logout()
                .logoutUrl(DEFAULT_LOGOUT_URL)
                .logoutSuccessUrl(environment.getProperty("front.endpoint.logout-success-page"))
                .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .and()
            .exceptionHandling()
                .defaultAuthenticationEntryPointFor(LoginUrlAuthenticationEntryPoint(DEFAULT_LOGIN_PAGE), AntPathRequestMatcher("/oauth/authorize"))
    }

    override fun configure(web: WebSecurity) {
        web.ignoring().antMatchers("/css/**", "/img/**", "/js/**")
    }
}