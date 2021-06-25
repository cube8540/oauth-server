package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.oauth.AccessTokenIntrospectionKey
import cube8540.oauth.authentication.oauth.error.AbstractOAuth2AuthenticationException
import cube8540.oauth.authentication.oauth.error.InvalidRequestException.Companion.invalidRequest
import cube8540.oauth.authentication.oauth.error.OAuth2AccessTokenRegistrationException
import cube8540.oauth.authentication.oauth.error.OAuth2ExceptionTranslator
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetailsService
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsToken
import java.security.Principal
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class OAuth2TokenIntrospectionEndpoint @Autowired constructor(
    @Qualifier("oAuth2ClientNotCheckingAccessTokenDetailsService")
    private val service: OAuth2AccessTokenDetailsService
) {

    private val logger = LoggerFactory.getLogger(this.javaClass)

    var exceptionTranslator: ExceptionTranslator<OAuth2Error> = OAuth2ExceptionTranslator()

    var converter: OAuth2AccessTokenIntrospectionConverter = DefaultOAuth2AccessTokenIntrospectionConverter()

    @PostMapping(value = ["/oauth/token_info"])
    fun introspection(principal: Principal, @RequestParam(required = false) token: String?): Map<String, Any?> {
        if (token == null) {
            throw invalidRequest("access token is required")
        }

        if (principal !is ClientCredentialsToken || principal.principal !is OAuth2ClientDetails) {
            throw InsufficientAuthenticationException("this is no client authentication")
        }

        val accessToken = service.readAccessToken(token)
        return converter.convertAccessToken(accessToken)
    }

    @ExceptionHandler(value = [OAuth2AccessTokenRegistrationException::class])
    fun handleException(e: OAuth2AccessTokenRegistrationException): ResponseEntity<OAuth2Error> {
        logger.warn("Handling error {} {}", e.javaClass, e.message)
        return exceptionTranslator.translate(e)
    }

    @ExceptionHandler(value = [AbstractOAuth2AuthenticationException::class])
    fun handleException(e: AbstractOAuth2AuthenticationException): ResponseEntity<OAuth2Error> {
        logger.warn("Handling error {} {}", e.javaClass, e.message)
        return exceptionTranslator.translate(e)
    }

    @ExceptionHandler(Exception::class)
    fun handleServerException(e: Exception): Map<String?, Boolean> {
        logger.error("Handling error {}, {}", e.javaClass, e.message)
        return mapOf(AccessTokenIntrospectionKey.ACTIVE to false)
    }
}