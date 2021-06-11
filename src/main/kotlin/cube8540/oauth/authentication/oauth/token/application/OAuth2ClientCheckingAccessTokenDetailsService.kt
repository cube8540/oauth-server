package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.error.InvalidClientException.Companion.invalidClient
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetailsService
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenNotFoundException
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenId
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service(value = "oAuth2ClientCheckingAccessTokenDetailsService")
class OAuth2ClientCheckingAccessTokenDetailsService @Autowired constructor(private val tokenRepository: OAuth2AccessTokenRepository): OAuth2AccessTokenDetailsService {

    @Transactional(readOnly = true)
    override fun readAccessToken(tokenValue: String): OAuth2AccessTokenDetails {
        val accessToken = tokenRepository.findById(OAuth2TokenId(tokenValue))
            .orElseThrow { OAuth2AccessTokenNotFoundException(tokenValue) }

        assertTokenClient(accessToken)
        return DefaultAccessTokenDetails.of(accessToken)
    }

    private fun assertTokenClient(accessToken: OAuth2AuthorizedAccessToken) {
        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication.name != accessToken.client.value) {
            throw invalidClient("client and access token client is different")
        }
    }
}