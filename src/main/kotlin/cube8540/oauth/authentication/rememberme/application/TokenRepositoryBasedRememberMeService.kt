package cube8540.oauth.authentication.rememberme.application

import cube8540.oauth.authentication.rememberme.domain.RememberMeToken
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenGenerator
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenRepository
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenSeries
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenValue
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices
import org.springframework.security.web.authentication.rememberme.CookieTheftException
import org.springframework.security.web.authentication.rememberme.InvalidCookieException
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class TokenRepositoryBasedRememberMeService constructor(
    key: String,
    private val generator: RememberMeTokenGenerator,
    private val repository: RememberMeTokenRepository,
    userDetailsService: UserDetailsService
): AbstractRememberMeServices(key, userDetailsService) {

    override fun onLoginSuccess(request: HttpServletRequest, response: HttpServletResponse, successfulAuthentication: Authentication) {
        val token = RememberMeToken(generator, successfulAuthentication.name)

        repository.save(token)
        setCookie(arrayOf(token.series.value, token.tokenValue.value), RememberMeToken.tokenValiditySeconds.toInt(), request, response)
    }

    override fun processAutoLoginCookie(cookieTokens: Array<out String>, request: HttpServletRequest, response: HttpServletResponse): UserDetails? {
        if (cookieTokens.size != 2) {
            throw InvalidCookieException("Cookie Token did not contain 2 tokens, but contained ${cookieTokens.joinToString(", ")}")
        }

        val seriesValue = RememberMeTokenSeries(cookieTokens[0])
        val tokenValue = RememberMeTokenValue(cookieTokens[1])

        val token = repository.findById(seriesValue)
            .orElseThrow { RememberMeAuthenticationException("No persistent token found for series id: ${seriesValue.value}") }

        if (token.tokenValue != tokenValue) {
            repository.delete(token)

            throw CookieTheftException(messages.getMessage(
                "PersistentTokenBasedRememberMeServices.cookieStolen",
                "Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."))
        }

        if (token.isExpired()) {
            repository.delete(token)

            throw RememberMeAuthenticationException("Remember me login has expired")
        }

        token.updateLastUsedAt()
        repository.save(token)

        return userDetailsService.loadUserByUsername(token.username.value)
    }

    override fun logout(request: HttpServletRequest, response: HttpServletResponse, authentication: Authentication) {
        super.logout(request, response, authentication)

        val cookieTokens = extractRememberMeCookie(request)
        if (cookieTokens != null) {
            repository.findById(RememberMeTokenSeries(decodeCookie(cookieTokens)[0]))
                .ifPresent { repository.delete(it) }
        }
    }
}