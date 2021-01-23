package cube8540.oauth.authentication.credentials.oauth.token.application

import cube8540.oauth.authentication.credentials.AuthorityCode
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Service
import java.time.LocalDateTime

@Service
class RefreshTokenGranter @Autowired constructor(
    tokenRepository: OAuth2AccessTokenRepository,

    @Qualifier("OAuth2RefreshTokenRepository")
    private val refreshTokenRepository: OAuth2RefreshTokenRepository,

    @Qualifier("defaultTokenIdGenerator")
    tokenIdGenerator: OAuth2TokenIdGenerator
): AbstractOAuth2TokenGranter(tokenIdGenerator, tokenRepository) {

    override fun createAccessToken(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): OAuth2AuthorizedAccessToken {
        if (tokenRequest.refreshToken == null) {
            throw InvalidRequestException.invalidRequest("refresh token is required")
        }
        val storedRefreshToken = refreshTokenRepository.findById(OAuth2TokenId(tokenRequest.refreshToken!!))
            .orElseThrow { InvalidGrantException.invalidGrant("invalid refresh token") }

        val storedAccessToken = storedRefreshToken.accessToken
        if (storedAccessToken.client != OAuth2ClientId(clientDetails.clientId)) {
            throw InvalidClientException.invalidClient("invalid refresh token")
        }

        refreshTokenRepository.delete(storedRefreshToken)
        if (storedRefreshToken.isExpired()) {
            throw InvalidGrantException.invalidGrant("refresh token is expired")
        }

        val storedAccessTokenScopes = storedAccessToken.scopes.map(AuthorityCode::value).toSet()
        if (!tokenRequestValidator.validateScopes(storedAccessTokenScopes, tokenRequest.scopes)) {
            throw InvalidGrantException.invalidScope("cannot grant scope")
        }

        val accessToken = makeNewToken(storedAccessToken, clientDetails, tokenRequest)
        accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails))
        accessToken.generateComposeUniqueKey(composeUniqueKeyGenerator)
        return accessToken
    }

    protected fun extractGrantScope(accessToken: OAuth2AuthorizedAccessToken, tokenRequest: OAuth2TokenRequest): Set<AuthorityCode> {
        return if (tokenRequest.scopes != null && tokenRequest.scopes!!.isNotEmpty()) {
            tokenRequest.scopes!!.map { code -> AuthorityCode(code) }.toSet()
        } else {
            accessToken.scopes.toSet()
        }
    }

    override fun isReturnsExistsToken(existsAccessToken: OAuth2AuthorizedAccessToken, newAccessToken: OAuth2AuthorizedAccessToken): Boolean = false

    private fun makeNewToken(storedAccessToken: OAuth2AuthorizedAccessToken, clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest) =
        OAuth2AuthorizedAccessToken(
            tokenIdGenerator = tokenIdGenerator,
            username = storedAccessToken.username,
            client = storedAccessToken.client,
            scopes = extractGrantScope(storedAccessToken, tokenRequest).toMutableSet(),
            tokenGrantType = storedAccessToken.tokenGrantType,
            expiration = extractTokenExpiration(clientDetails),
            issuedAt = LocalDateTime.now(clock)
        )

}