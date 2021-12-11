package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenGranter
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import org.hibernate.exception.LockAcquisitionException
import org.springframework.dao.DuplicateKeyException
import org.springframework.retry.annotation.Retryable
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.transaction.annotation.Transactional

open class CompositeOAuth2AccessTokenGranter: OAuth2AccessTokenGranter {

    private val tokenGranterMap: MutableMap<AuthorizationGrantType, OAuth2AccessTokenGranter> = HashMap()

    @Retryable(value = [LockAcquisitionException::class, DuplicateKeyException::class])
    @Transactional(noRollbackFor = [InvalidGrantException::class])
    override fun grant(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): OAuth2AccessTokenDetails {
        val granter = tokenGranterMap[tokenRequest.grantType] ?: throw InvalidGrantException.unsupportedGrantType("unsupported grant type")
        return granter.grant(clientDetails, tokenRequest)
    }

    fun putTokenGranterMap(grantType: AuthorizationGrantType, tokenGranter: OAuth2AccessTokenGranter) {
        tokenGranterMap[grantType] = tokenGranter
    }
}