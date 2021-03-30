package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator
import cube8540.oauth.authentication.oauth.token.domain.PrincipalUsername
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.stereotype.Service
import java.time.LocalDateTime

@Service
class ImplicitTokenGranter @Autowired constructor(
    @Qualifier("defaultTokenIdGenerator")
    tokenIdGenerator: OAuth2TokenIdGenerator,

    tokenRepository: OAuth2AccessTokenRepository
): AbstractOAuth2TokenGranter(tokenIdGenerator, tokenRepository) {

    override fun createAccessToken(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): OAuth2AuthorizedAccessToken {
        if (tokenRequest.username == null) {
            throw InvalidRequestException.invalidRequest("username is required")
        }
        return OAuth2AuthorizedAccessToken(
            tokenIdGenerator = tokenIdGenerator,
            username = PrincipalUsername(tokenRequest.username!!),
            client = OAuth2ClientId(clientDetails.clientId),
            scopes = extractGrantScope(clientDetails, tokenRequest).toMutableSet(),
            expiration = extractTokenExpiration(clientDetails),
            tokenGrantType = AuthorizationGrantType.IMPLICIT,
            issuedAt = LocalDateTime.now(clock)
        )
    }
}