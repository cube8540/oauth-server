package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetailsService
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenNotFoundException
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenId
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service(value = "oAuth2ClientNotCheckingAccessTokenDetailsService")
class OAuth2ClientNotCheckingAccessTokenDetailsService @Autowired constructor(private val tokenRepository: OAuth2AccessTokenRepository): OAuth2AccessTokenDetailsService {

    @Transactional(readOnly = true)
    override fun readAccessToken(tokenValue: String): OAuth2AccessTokenDetails {
        val accessToken = tokenRepository.findById(OAuth2TokenId(tokenValue))
            .orElseThrow { OAuth2AccessTokenNotFoundException(tokenValue) }
        return DefaultAccessTokenDetails.of(accessToken)
    }
}