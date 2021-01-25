package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.error.InvalidClientException.Companion.invalidClient
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetailsService
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenNotFoundException
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenId
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.core.CredentialsContainer
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class DefaultOAuth2AccessTokenDetailsService @Autowired constructor(
    private val tokenRepository: OAuth2AccessTokenRepository,

    @Qualifier("defaultUserService")
    private val userDetailsService: UserDetailsService
): OAuth2AccessTokenDetailsService {

    @Transactional(readOnly = true)
    override fun readAccessToken(tokenValue: String): OAuth2AccessTokenDetails {
        val accessToken = tokenRepository.findById(OAuth2TokenId(tokenValue))
            .orElseThrow { OAuth2AccessTokenNotFoundException(tokenValue) }

        assertTokenClient(accessToken)
        return DefaultAccessTokenDetails.of(accessToken)
    }

    @Transactional(readOnly = true)
    override fun readAccessTokenUser(tokenValue: String): UserDetails {
        val accessToken = tokenRepository.findById(OAuth2TokenId(tokenValue))
            .orElseThrow { OAuth2AccessTokenNotFoundException(tokenValue) }

        assertTokenClient(accessToken)

        if (accessToken.username == null) {
            throw InvalidRequestException.invalidRequest("token is not generated for user")
        }
        return getUserDetails(accessToken.username!!.value)
    }

    private fun getUserDetails(username: String): UserDetails {
        val user = userDetailsService.loadUserByUsername(username)
        if (user is CredentialsContainer) {
            user.eraseCredentials()
        }
        return user
    }

    private fun assertTokenClient(accessToken: OAuth2AuthorizedAccessToken) {
        val authentication = SecurityContextHolder.getContext().authentication
        if (authentication.name != accessToken.client.value) {
            throw invalidClient("client and access token client is different")
        }
    }
}