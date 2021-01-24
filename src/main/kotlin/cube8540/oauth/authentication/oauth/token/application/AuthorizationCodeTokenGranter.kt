package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCode
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import org.springframework.stereotype.Service
import java.net.URI
import java.time.LocalDateTime
import java.util.*

@Service
class AuthorizationCodeTokenGranter @Autowired constructor(
    @Qualifier("defaultTokenIdGenerator")
    tokenIdGenerator: OAuth2TokenIdGenerator,

    tokenRepository: OAuth2AccessTokenRepository,

    @Qualifier("compositionAuthorizationCodeService")
    private val authorizationCodeConsumer: OAuth2AuthorizationCodeConsumer
): AbstractOAuth2TokenGranter(tokenIdGenerator, tokenRepository) {

    override fun createAccessToken(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): OAuth2AuthorizedAccessToken {
        if (tokenRequest.code == null) {
            throw InvalidRequestException.invalidRequest("authorization code is required")
        }
        val authorizationCode = authorizationCodeConsumer.consume(tokenRequest.code!!)
            .orElseThrow { InvalidRequestException.invalidRequest("authorization code not found") }

        val authorizationCodeScope: Set<String> = authorizationCode.approvedScopes?.map(AuthorityCode::value)?.toSet() ?: Collections.emptySet()
        if (authorizationCodeScope.isEmpty()) {
            throw InvalidGrantException.invalidScope("cannot grant empty scope")
        }
        if (!tokenRequestValidator.validateScopes(clientDetails, authorizationCodeScope)) {
            throw InvalidGrantException.invalidScope("cannot grant scope")
        }
        authorizationCode.validateWithAuthorizationRequest(AuthorizationCodeRequest(clientDetails, tokenRequest))

        val accessToken = makeNewToken(clientDetails, authorizationCode)
        accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails))
        accessToken.generateComposeUniqueKey(composeUniqueKeyGenerator)
        return accessToken
    }

    private fun makeNewToken(clientDetails: OAuth2ClientDetails, authorizationCode: OAuth2AuthorizationCode) =
        OAuth2AuthorizedAccessToken(
            tokenIdGenerator = tokenIdGenerator,
            username = authorizationCode.username,
            client = OAuth2ClientId(clientDetails.clientId),
            scopes = authorizationCode.approvedScopes!!,
            tokenGrantType = AuthorizationGrantType.AUTHORIZATION_CODE,
            expiration = extractTokenExpiration(clientDetails),
            issuedAt = LocalDateTime.now(clock)
        )

    private data class AuthorizationCodeRequest(
        private val clientDetails: OAuth2ClientDetails,

        private val tokenRequest: OAuth2TokenRequest
    ): AuthorizationRequest {

        override val clientId: String = clientDetails.clientId

        override val username: String? = tokenRequest.username

        override val state: String? = tokenRequest.state

        override var redirectUri: URI? = tokenRequest.redirectUri
            set(_) = throw UnsupportedOperationException("${this.javaClass.name}#setRedirectURI")

        override var requestScopes: Set<String>? = tokenRequest.scopes
            set(_) = throw UnsupportedOperationException("${this.javaClass.name}#setRequestScopes")

        override val responseType: OAuth2AuthorizationResponseType = OAuth2AuthorizationResponseType.CODE
    }
}