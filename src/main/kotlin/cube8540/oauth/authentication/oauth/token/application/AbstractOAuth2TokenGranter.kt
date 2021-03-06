package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.AuthenticationApplication
import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.oauth.security.DefaultOAuth2RequestValidator
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenGranter
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2ComposeUniqueKey
import cube8540.oauth.authentication.oauth.token.domain.OAuth2ComposeUniqueKeyGenerator
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenEnhancer
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator
import org.springframework.beans.factory.annotation.Autowired
import java.time.Clock
import java.time.LocalDateTime

abstract class AbstractOAuth2TokenGranter(
    internal var tokenIdGenerator: OAuth2TokenIdGenerator,

    internal var tokenRepository: OAuth2AccessTokenRepository
): OAuth2AccessTokenGranter {

    companion object {
        @JvmStatic
        protected var clock: Clock = AuthenticationApplication.DEFAULT_CLOCK
    }

    var refreshTokenIdGenerator: OAuth2TokenIdGenerator? = null

    var tokenRequestValidator: OAuth2RequestValidator = DefaultOAuth2RequestValidator()

    var tokenEnhancer: OAuth2TokenEnhancer = NullOAuth2TokenEnhancer()

    @set:[Autowired]
    var composeUniqueKeyGenerator: OAuth2ComposeUniqueKeyGenerator = DefaultOAuth2ComposeUniqueKeyGenerator()

    override fun grant(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): OAuth2AccessTokenDetails {
        val accessToken = createAccessToken(clientDetails, tokenRequest)
        accessToken.generateComposeUniqueKey(composeUniqueKeyGenerator)

        val existsAccessToken = tokenRepository.findByComposeUniqueKey(accessToken.composeUniqueKey!!)
        if (existsAccessToken.isPresent && isReturnsExistsToken(existsAccessToken.get(), accessToken)) {
            return DefaultAccessTokenDetails.of(existsAccessToken.get())
        }
        existsAccessToken.ifPresent(this::deleteExistsAccessToken)
        tokenEnhancer.enhance(accessToken)
        tokenRepository.save(accessToken)
        return DefaultAccessTokenDetails.of(accessToken)
    }

    internal abstract fun createAccessToken(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): OAuth2AuthorizedAccessToken

    internal open fun extractTokenExpiration(clientDetails: OAuth2ClientDetails): LocalDateTime =
        LocalDateTime.now(clock).plusSeconds(clientDetails.accessTokenValiditySeconds?.toLong() ?: 0)

    internal open fun extractRefreshTokenExpiration(clientDetails: OAuth2ClientDetails): LocalDateTime =
        LocalDateTime.now(clock).plusSeconds(clientDetails.refreshTokenValiditySeconds?.toLong() ?: 0)

    internal open fun extractGrantScope(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): Set<AuthorityCode> {
        return if (tokenRequest.scopes != null && tokenRequest.scopes!!.isNotEmpty()) {
            tokenRequest.scopes!!.map { AuthorityCode(it) }.toSet()
        } else {
            clientDetails.scopes.map { AuthorityCode(it) }.toSet()
        }
    }

    internal fun refreshTokenGenerator() = refreshTokenIdGenerator ?: tokenIdGenerator

    internal open fun isReturnsExistsToken(existsAccessToken: OAuth2AuthorizedAccessToken, newAccessToken: OAuth2AuthorizedAccessToken) =
        (existsAccessToken.tokenGrantType == newAccessToken.tokenGrantType) && !existsAccessToken.isExpired()

    private fun deleteExistsAccessToken(existsAccessToken: OAuth2AuthorizedAccessToken) {
        tokenRepository.delete(existsAccessToken)
        tokenRepository.flush()
    }

    private inner class NullOAuth2TokenEnhancer: OAuth2TokenEnhancer {
        override fun enhance(accessToken: OAuth2AuthorizedAccessToken) {
            // Do nothing...
        }
    }

    private inner class DefaultOAuth2ComposeUniqueKeyGenerator: OAuth2ComposeUniqueKeyGenerator {
        override fun generateKey(token: OAuth2AuthorizedAccessToken): OAuth2ComposeUniqueKey =
            OAuth2ComposeUniqueKey(token.tokenId.value)
    }
}