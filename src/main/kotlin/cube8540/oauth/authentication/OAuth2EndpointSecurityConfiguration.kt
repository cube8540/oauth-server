package cube8540.oauth.authentication

import com.fasterxml.jackson.databind.ObjectMapper
import cube8540.oauth.authentication.oauth.error.OAuth2ExceptionResponseRenderer
import cube8540.oauth.authentication.oauth.error.OAuth2ExceptionTranslator
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenGranter
import cube8540.oauth.authentication.oauth.security.OAuth2AuthorizationCodeGenerator
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationCodeResponseEnhancer
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationResponseEnhancer
import cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsAuthenticationProvider
import cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsEndpointFilter
import cube8540.oauth.authentication.oauth.token.application.AuthorizationCodeTokenGranter
import cube8540.oauth.authentication.oauth.token.application.ClientCredentialsTokenGranter
import cube8540.oauth.authentication.oauth.token.application.CompositeOAuth2AccessTokenGranter
import cube8540.oauth.authentication.oauth.token.application.ImplicitTokenGranter
import cube8540.oauth.authentication.oauth.token.application.RefreshTokenGranter
import cube8540.oauth.authentication.oauth.token.application.ResourceOwnerPasswordTokenGranter
import cube8540.oauth.authentication.error.DefaultAuthenticationExceptionEntryPoint
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationImplicitResponseEnhancer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.core.annotation.Order
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.context.NullSecurityContextRepository
import org.springframework.web.cors.CorsConfiguration
import javax.annotation.PostConstruct

@Order(1)
@EnableWebSecurity
class OAuth2EndpointSecurityConfiguration: WebSecurityConfigurerAdapter() {

    @set:[Autowired Qualifier("defaultOAuth2ClientDetailsService")]
    lateinit var clientDetailsService: OAuth2ClientDetailsService

    @set:[Autowired Qualifier("defaultUserService")]
    lateinit var userDetailsService: UserDetailsService

    @set:[Autowired]
    lateinit var passwordEncoder: PasswordEncoder

    @set:[Autowired Qualifier("escapeObjectMapper")]
    lateinit var objectMapper: ObjectMapper

    var entryPoint: AuthenticationEntryPoint? = null

    @PostConstruct
    fun initialize() {
        this.entryPoint = DefaultAuthenticationExceptionEntryPoint(
            OAuth2ExceptionTranslator(),
            OAuth2ExceptionResponseRenderer(MappingJackson2HttpMessageConverter(objectMapper)))
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder)
            .and()
            .authenticationProvider(clientCredentialsAuthenticationProvider())
    }

    @Bean(name = ["oauthAuthenticationBean"])
    override fun authenticationManagerBean(): AuthenticationManager = super.authenticationManagerBean()

    override fun configure(http: HttpSecurity) {
        http.requestMatchers()
                .antMatchers("/oauth/token", "/oauth/token_info", "/oauth/user_info")
                .and()
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .addFilterBefore(tokenEndpointClientCredentialsFilter(), UsernamePasswordAuthenticationFilter::class.java)
            .securityContext()
                .securityContextRepository(NullSecurityContextRepository())
                .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
            .csrf().disable()
            .cors().configurationSource { CorsConfiguration().applyPermitDefaultValues() }
    }

    @Bean
    fun tokenEndpointClientCredentialsFilter(): ClientCredentialsEndpointFilter {
        val filter = ClientCredentialsEndpointFilter("/oauth/**")

        filter.entryPoint = entryPoint
        filter.setAuthenticationManager(authenticationManagerBean())

        return filter
    }

    @Bean
    fun clientCredentialsAuthenticationProvider() = ClientCredentialsAuthenticationProvider(clientDetailsService, passwordEncoder)

    @Bean
    @Autowired
    fun authorizationResponseEnhancer(accessTokenGranter: OAuth2AccessTokenGranter,
            codeGranter:OAuth2AuthorizationCodeGenerator): AuthorizationResponseEnhancer {
        val enhancer: AuthorizationResponseEnhancer = AuthorizationCodeResponseEnhancer(codeGranter)
        enhancer.setNext(AuthorizationImplicitResponseEnhancer(accessTokenGranter, clientDetailsService))

        return enhancer
    }

    @Bean
    @Autowired
    fun accessTokenGranter(authorizationCodeTokenGranter: AuthorizationCodeTokenGranter,
            refreshTokenGranter: RefreshTokenGranter,
            clientCredentialsTokenGranter: ClientCredentialsTokenGranter,
            implicitTokenGranter: ImplicitTokenGranter,
            resourceOwnerPasswordTokenGranter: ResourceOwnerPasswordTokenGranter): OAuth2AccessTokenGranter {

        val tokenGranter = CompositeOAuth2AccessTokenGranter()

        tokenGranter.putTokenGranterMap(AuthorizationGrantType.AUTHORIZATION_CODE, authorizationCodeTokenGranter)
        tokenGranter.putTokenGranterMap(AuthorizationGrantType.REFRESH_TOKEN, refreshTokenGranter)
        tokenGranter.putTokenGranterMap(AuthorizationGrantType.CLIENT_CREDENTIALS, clientCredentialsTokenGranter)
        tokenGranter.putTokenGranterMap(AuthorizationGrantType.IMPLICIT, implicitTokenGranter)
        tokenGranter.putTokenGranterMap(AuthorizationGrantType.PASSWORD, resourceOwnerPasswordTokenGranter)

        return tokenGranter
    }

}