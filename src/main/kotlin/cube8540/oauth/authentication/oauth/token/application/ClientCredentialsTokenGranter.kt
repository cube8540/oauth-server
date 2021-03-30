package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.stereotype.Service
import java.time.LocalDateTime

@Service
class ClientCredentialsTokenGranter @Autowired constructor(
    @Qualifier("defaultTokenIdGenerator")
    tokenIdGenerator: OAuth2TokenIdGenerator,

    tokenRepository: OAuth2AccessTokenRepository
): AbstractOAuth2TokenGranter(tokenIdGenerator, tokenRepository) {

    var allowedRefreshToken: Boolean = false

    override fun createAccessToken(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): OAuth2AuthorizedAccessToken {
        if (!tokenRequestValidator.validateScopes(clientDetails, tokenRequest.scopes)) {
            throw InvalidGrantException.invalidScope("cannot grant scope")
        }

        val accessToken = makeNewToken(clientDetails, tokenRequest)
        if (allowedRefreshToken) {
            accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails))
        }
        return accessToken
    }

    private fun makeNewToken(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest) = OAuth2AuthorizedAccessToken(
        tokenIdGenerator = tokenIdGenerator,
        username = null,
        client = OAuth2ClientId(clientDetails.clientId),
        scopes = extractGrantScope(clientDetails, tokenRequest).toMutableSet(),
        expiration = extractTokenExpiration(clientDetails),
        tokenGrantType = AuthorizationGrantType.CLIENT_CREDENTIALS,
        issuedAt = LocalDateTime.now(clock)
    )
}