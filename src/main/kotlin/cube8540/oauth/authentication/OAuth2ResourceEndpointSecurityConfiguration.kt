package cube8540.oauth.authentication

import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetailsService
import cube8540.oauth.authentication.oauth.security.introspector.DefaultAccessTokenIntrospector
import cube8540.oauth.authentication.security.RoleSecurityConfig
import cube8540.oauth.authentication.security.ScopeSecurityConfig
import cube8540.oauth.authentication.security.TypeBasedAuthorityVoter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.core.annotation.Order
import org.springframework.core.env.Environment
import org.springframework.security.access.AccessDecisionManager
import org.springframework.security.access.AccessDecisionVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.access.vote.UnanimousBased
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.web.cors.CorsConfiguration
import java.util.*

@Order(3)
@EnableWebSecurity
class OAuth2ResourceEndpointSecurityConfiguration: WebSecurityConfigurerAdapter() {

    @set:[Autowired]
    lateinit var environment: Environment

    @set:[Autowired]
    lateinit var securityMetadataLoadService: FilterInvocationSecurityMetadataSource

    @set:[Autowired Qualifier("oAuth2ClientNotCheckedAccessTokenDetailsService")]
    lateinit var accessTokenService: OAuth2AccessTokenDetailsService

    @set:[Autowired Qualifier("clientCredentialsAuthenticationProvider")]
    lateinit var authenticationProvider: AuthenticationProvider

    override fun configure(http: HttpSecurity) {
        http.oauth2ResourceServer()
                .opaqueToken { it.introspector(accessTokenIntrospector()) }
                .and()
            .cors()
                .configurationSource { CorsConfiguration().applyPermitDefaultValues() }
                .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
            .addFilterAfter(filterSecurityInterceptor(), FilterSecurityInterceptor::class.java)
            .csrf().disable()
    }

    @Bean
    @Throws(Exception::class)
    fun filterSecurityInterceptor(): FilterSecurityInterceptor {
        val filterSecurityInterceptor = FilterSecurityInterceptor()
        filterSecurityInterceptor.authenticationManager = authenticationManagerBean()
        filterSecurityInterceptor.securityMetadataSource = securityMetadataLoadService
        filterSecurityInterceptor.accessDecisionManager = accessDecisionManager()
        return filterSecurityInterceptor
    }

    private fun accessDecisionManager(): AccessDecisionManager {
        val accessDecisionVoters: MutableList<AccessDecisionVoter<*>> = ArrayList()
        accessDecisionVoters.add(createRoleAuthorityVoter())
        accessDecisionVoters.add(createScopeAuthorityVoter())
        return UnanimousBased(accessDecisionVoters)
    }

    private fun createRoleAuthorityVoter(): RoleVoter {
        val roleVoter = TypeBasedAuthorityVoter(RoleSecurityConfig::class.java)
        roleVoter.rolePrefix = ""
        return roleVoter
    }

    private fun createScopeAuthorityVoter(): RoleVoter {
        val roleVoter = TypeBasedAuthorityVoter(ScopeSecurityConfig::class.java)
        roleVoter.rolePrefix = ""
        return roleVoter
    }

    private fun accessTokenIntrospector(): DefaultAccessTokenIntrospector {
        val introspector = DefaultAccessTokenIntrospector(accessTokenService, authenticationProvider)
        introspector.clientId = environment.getProperty("oauth-resource-server.client-id")
        introspector.clientSecret = environment.getProperty("oauth-resource-server.client-secret")
        return introspector
    }
}