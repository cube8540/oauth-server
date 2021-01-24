package cube8540.oauth.authentication.oauth.security.provider

import cube8540.oauth.authentication.oauth.error.InvalidClientException
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.web.HttpRequestMethodNotSupportedException
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class ClientCredentialsEndpointFilter(requestMatcher: RequestMatcher): AbstractAuthenticationProcessingFilter(requestMatcher) {

    var entryPoint: AuthenticationEntryPoint? = null

    var converter: AuthenticationConverter = BasicAuthenticationConverter()

    var onlyPost = false

    init {
        setRequiresAuthenticationRequestMatcher(requestMatcher)
    }

    constructor(endpoint: String): this(AntPathRequestMatcher(endpoint))

    override fun afterPropertiesSet() {
        super.afterPropertiesSet()
        // 아무 행동도 하지 않고 다음 필터로 넘어가도록 설정한다.
        setAuthenticationSuccessHandler { _, _, _ ->  }
        setAuthenticationFailureHandler { request, response, exception ->
            var e = exception
            if (exception != null && exception is BadCredentialsException) {
                e = exception.message?.let { InvalidClientException.unauthorizedClient(it) }
            }
            entryPoint!!.commence(request, response, e)
        }
    }

    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        if (onlyPost && !request.method.equals(other = "POST", ignoreCase = true)) {
            throw HttpRequestMethodNotSupportedException(request.method, "POST")
        }

        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication != null && authentication.isAuthenticated) {
            return authentication
        }
        return authenticationManager.authenticate(extractClientAuthentication(request))
    }

    override fun successfulAuthentication(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain, authResult: Authentication) {
        super.successfulAuthentication(request, response, chain, authResult)
        chain.doFilter(request, response)
    }

    private fun extractClientAuthentication(request: HttpServletRequest): ClientCredentialsToken {
        val basicAuthenticationToken: Authentication? = converter.convert(request)

        val clientId = basicAuthenticationToken?.principal?.toString() ?: request.getParameter("client_id")
        val clientSecret = basicAuthenticationToken?.credentials?.toString() ?: request.getParameter("client_secret")

        if (clientId == null) {
            throw BadCredentialsException("No client credentials presented")
        }

        return ClientCredentialsToken(clientId, clientSecret)
    }

}