package cube8540.oauth.authentication.credentials.oauth.token.application

import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRevoker
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Service

@Service
class ClientAuthenticationBaseTokenRevoker @Autowired constructor(
    private val repository: OAuth2AccessTokenRepository
): OAuth2TokenRevoker {

    override fun revoke(tokenValue: String): OAuth2AccessTokenDetails {
        val accessToken = repository.findById(OAuth2TokenId(tokenValue))
            .orElseThrow { OAuth2AccessTokenNotFoundException(tokenValue) }

        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication.name != accessToken.client.value) {
            throw InvalidClientException.invalidClient("client and access token client is different")
        }
        repository.delete(accessToken)
        return DefaultAccessTokenDetails.of(accessToken)
    }
}