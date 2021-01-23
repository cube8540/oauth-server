package cube8540.oauth.authentication.credentials.oauth.token.application

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRevoker
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId
import cube8540.oauth.authentication.credentials.oauth.token.domain.TokenNotFoundException.Companion.instance
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class DefaultTokenRevoker @Autowired constructor(
    private val repository: OAuth2AccessTokenRepository
): OAuth2TokenRevoker {

    @Transactional
    override fun revoke(tokenValue: String): OAuth2AccessTokenDetails {
        val token = repository.findById(OAuth2TokenId(tokenValue))
            .orElseThrow { instance("$tokenValue is not found") }

        repository.delete(token)
        return DefaultAccessTokenDetails.of(token)
    }
}