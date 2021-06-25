package cube8540.oauth.authentication.oauth.token.application

import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCode
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator
import cube8540.oauth.authentication.security.AuthorityCode
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.stereotype.Service
import java.net.URI
import java.time.LocalDateTime

@Service
class AuthorizationCodeTokenGranter @Autowired constructor(
    @Qualifier("defaultTokenIdGenerator")
    tokenIdGenerator: OAuth2TokenIdGenerator,

    tokenRepository: OAuth2AccessTokenRepository,

    @Qualifier("compositionAuthorizationCodeService")
    private val authorizationCodeConsumer: OAuth2AuthorizationCodeConsumer
): AbstractOAuth2TokenGranter(tokenIdGenerator, tokenRepository) {

    override fun createAccessToken(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): OAuth2AuthorizedAccessToken {
        val requestToken = tokenRequest.code ?: throw InvalidRequestException.invalidRequest("authorization code is required")
        val authorizationCode = authorizationCodeConsumer.consume(requestToken)
            ?: throw InvalidRequestException.invalidRequest("authorization code not found")

        val authorizationCodeScope: Set<String> = authorizationCode.approvedScopes?.map(AuthorityCode::value)?.toSet() ?: emptySet()
        if (authorizationCodeScope.isEmpty()) {
            throw InvalidGrantException.invalidScope("cannot grant empty scope")
        }
        if (!tokenRequestValidator.validateScopes(clientDetails, authorizationCodeScope)) {
            throw InvalidGrantException.invalidScope("cannot grant scope")
        }
        authorizationCode.validateWithAuthorizationRequest(AuthorizationCodeGrantRequest(clientDetails, tokenRequest))

        val accessToken = makeNewToken(clientDetails, authorizationCode)
        accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails))

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

    private data class AuthorizationCodeGrantRequest(
        private val clientDetails: OAuth2ClientDetails,

        private val tokenRequest: OAuth2TokenRequest
    ): OAuth2TokenRequest {
        override val grantType: AuthorizationGrantType = AuthorizationGrantType.AUTHORIZATION_CODE

        override val username: String? = tokenRequest.username

        override val password: String? = null

        override val clientId: String = clientDetails.clientId

        override val refreshToken: String? = null

        override val code: String? = tokenRequest.code

        override val state: String? = tokenRequest.state

        override val redirectUri: URI? = tokenRequest.redirectUri

        override val scopes: Set<String>? = tokenRequest.scopes

        override val codeVerifier: CodeVerifier? = tokenRequest.codeVerifier

    }
}