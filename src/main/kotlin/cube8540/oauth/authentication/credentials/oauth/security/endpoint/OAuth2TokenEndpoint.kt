package cube8540.oauth.authentication.credentials.oauth.security.endpoint

import cube8540.oauth.authentication.credentials.oauth.TokenRequestKey
import cube8540.oauth.authentication.credentials.oauth.error.AbstractOAuth2AuthenticationException
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException.Companion.unsupportedGrantType
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException.Companion.invalidRequest
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator
import cube8540.oauth.authentication.credentials.oauth.security.DefaultOAuth2TokenRequest
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRevoker
import cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsToken
import cube8540.oauth.authentication.error.ExceptionTranslator
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.http.CacheControl
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

@RestController
class OAuth2TokenEndpoint @Autowired constructor(
    @Qualifier("accessTokenGranter") private val tokenGranter: OAuth2AccessTokenGranter,
    @Qualifier("clientAuthenticationBaseTokenRevoker") private val tokenRevoker: OAuth2TokenRevoker
) {

    private val logger = LoggerFactory.getLogger(this.javaClass)

    var exceptionTranslator: ExceptionTranslator<OAuth2Error> = OAuth2ExceptionTranslator()

    @PostMapping(value = ["/oauth/token"])
    fun grantNewAccessToken(principal: Principal, @RequestParam requestMap: Map<String, String?>): ResponseEntity<OAuth2AccessTokenDetails> {
        if (principal !is ClientCredentialsToken || principal.principal !is OAuth2ClientDetails) {
            throw InsufficientAuthenticationException("this is no client authentication")
        }

        if (requestMap[TokenRequestKey.GRANT_TYPE] == null) {
            throw invalidRequest("grant type is required")
        }

        if (requestMap[TokenRequestKey.GRANT_TYPE]!!.toLowerCase() == AuthorizationGrantType.IMPLICIT.value) {
            throw unsupportedGrantType("implicit grant type not supported")
        }

        val tokenRequest = DefaultOAuth2TokenRequest(requestMap)
        val token = tokenGranter.grant((principal.principal as OAuth2ClientDetails), tokenRequest)
        return createAccessTokenResponse(token)
    }

    @DeleteMapping(value = ["/oauth/token"])
    fun revokeAccessToken(principal: Principal, @RequestParam(required = false) token: String?): ResponseEntity<OAuth2AccessTokenDetails> {
        if (principal !is ClientCredentialsToken) {
            throw InsufficientAuthenticationException("this is no client authentication")
        }

        if (token == null) {
            throw invalidRequest("Token is required")
        }

        val accessToken = tokenRevoker.revoke(token)
        return createAccessTokenResponse(accessToken)
    }

    @ExceptionHandler(value = [Exception::class])
    fun handleException(e: Exception): ResponseEntity<OAuth2Error> {
        logger.error("Handling error: {}, {}", e.javaClass, e.message)
        return exceptionTranslator.translate(e)
    }

    @ExceptionHandler(value = [AbstractOAuth2AuthenticationException::class])
    fun handleException(e: AbstractOAuth2AuthenticationException): ResponseEntity<OAuth2Error> {
        logger.warn("Handling error: {}, {}", e.javaClass, e.message)
        return exceptionTranslator.translate(e)
    }

    private fun createAccessTokenResponse(token: OAuth2AccessTokenDetails): ResponseEntity<OAuth2AccessTokenDetails> {
        val headers = HttpHeaders()

        headers.setCacheControl(CacheControl.noStore())
        headers.pragma = "no-cache"
        headers.contentType = MediaType.APPLICATION_JSON
        return ResponseEntity(token, headers, HttpStatus.OK)
    }
}