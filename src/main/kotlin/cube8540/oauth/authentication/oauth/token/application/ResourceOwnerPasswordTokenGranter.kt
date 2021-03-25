package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.error.UserDeniedAuthorizationException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator
import cube8540.oauth.authentication.oauth.token.domain.PrincipalUsername
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.authentication.AccountStatusException
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.stereotype.Service
import java.time.LocalDateTime

@Service
class ResourceOwnerPasswordTokenGranter @Autowired constructor(
    @Qualifier("defaultTokenIdGenerator")
    tokenIdGenerator: OAuth2TokenIdGenerator,

    tokenRepository: OAuth2AccessTokenRepository,

    @Qualifier("oauthAuthenticationBean")
    private val authenticationManager: AuthenticationManager
): AbstractOAuth2TokenGranter(tokenIdGenerator, tokenRepository) {

    override fun createAccessToken(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): OAuth2AuthorizedAccessToken {
        if (tokenRequest.username == null || tokenRequest.password == null) {
            throw InvalidRequestException.invalidRequest("username, password is required")
        }
        if (!tokenRequestValidator.validateScopes(clientDetails, tokenRequest.scopes)) {
            throw InvalidGrantException.invalidScope("cannot grant scope")
        }

        val authentication = authentication(tokenRequest)
        val accessToken = OAuth2AuthorizedAccessToken(
            tokenIdGenerator = tokenIdGenerator,
            username = PrincipalUsername(authentication.name),
            client = OAuth2ClientId(clientDetails.clientId),
            scopes = extractGrantScope(clientDetails, tokenRequest).toMutableSet(),
            expiration = extractTokenExpiration(clientDetails),
            tokenGrantType = AuthorizationGrantType.PASSWORD,
            issuedAt = LocalDateTime.now(clock)
        )
        accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails))
        return accessToken
    }

    private fun authentication(tokenRequest: OAuth2TokenRequest): Authentication {
        try {
            val usernamePasswordToken = UsernamePasswordAuthenticationToken(tokenRequest.username, tokenRequest.password)
            return authenticationManager.authenticate(usernamePasswordToken)
        } catch (exception: Exception) {
            if (exception is BadCredentialsException || exception is AccountStatusException) {
                throw UserDeniedAuthorizationException(exception.message)
            } else {
                throw exception
            }
        }
    }

}