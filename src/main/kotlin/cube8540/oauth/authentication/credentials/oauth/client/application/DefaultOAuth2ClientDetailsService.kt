package cube8540.oauth.authentication.credentials.oauth.client.application

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ClientRegistrationException
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetailsService
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class DefaultOAuth2ClientDetailsService(private val repository: OAuth2ClientRepository): OAuth2ClientDetailsService {

    @Transactional(readOnly = true)
    override fun loadClientDetailsByClientId(clientId: String): OAuth2ClientDetails =
        repository.findByClientId(OAuth2ClientId(clientId))
            .map(DefaultOAuth2ClientDetails::of)
            .orElseThrow { OAuth2ClientRegistrationException("$clientId is not found") }
}