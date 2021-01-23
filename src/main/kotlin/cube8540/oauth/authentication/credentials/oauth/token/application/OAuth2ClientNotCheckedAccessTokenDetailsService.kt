package cube8540.oauth.authentication.credentials.oauth.token.application

import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetailsService
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.core.CredentialsContainer
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service(value = "oAuth2ClientNotCheckedAccessTokenDetailsService")
class OAuth2ClientNotCheckedAccessTokenDetailsService @Autowired constructor(
    private val tokenRepository: OAuth2AccessTokenRepository,
    @Qualifier("defaultUserService") private val userDetailsService: UserDetailsService
): OAuth2AccessTokenDetailsService {

    @Transactional(readOnly = true)
    override fun readAccessToken(tokenValue: String): OAuth2AccessTokenDetails {
        val accessToken = tokenRepository.findById(OAuth2TokenId(tokenValue))
            .orElseThrow { OAuth2AccessTokenNotFoundException(tokenValue) }
        return DefaultAccessTokenDetails.of(accessToken)
    }

    @Transactional(readOnly = true)
    override fun readAccessTokenUser(tokenValue: String): UserDetails {
        val accessToken = tokenRepository.findById(OAuth2TokenId(tokenValue))
            .orElseThrow { OAuth2AccessTokenNotFoundException(tokenValue) }

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
}