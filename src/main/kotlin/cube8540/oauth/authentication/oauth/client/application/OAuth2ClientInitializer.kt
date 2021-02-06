package cube8540.oauth.authentication.oauth.client.application

import cube8540.oauth.authentication.ApplicationInitializer
import cube8540.oauth.authentication.oauth.client.domain.ClientOwner
import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientRepository
import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.security.AuthorityDetails
import cube8540.oauth.authentication.security.AuthorityDetailsService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer
import org.springframework.context.ApplicationListener
import org.springframework.core.annotation.Order
import org.springframework.core.env.Environment
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.stereotype.Service
import java.net.URI
import javax.servlet.ServletContext

@Service
@Order(2)
class OAuth2ClientInitializer @Autowired constructor(
    private val repository: OAuth2ClientRepository,

    private val encoder: PasswordEncoder,

    private val authorityDetailsService: AuthorityDetailsService
): ApplicationInitializer, ApplicationListener<ApplicationReadyEvent> {

    companion object {
        const val USERNAME_KEY = "init-user.username"

        const val CLIENT_ID_KEY = "init-oauth-client.client-id"
        const val CLIENT_SECRET_KEY = "init-oauth-client.client-secret"
        const val CLIENT_NAME = "init-oauth-client.client-name"
        const val CLIENT_GRANT_TYPE_KEY = "init-oauth-client.client-grant-type"
        const val CLIENT_REDIRECT_URI = "init-oauth-client.client-redirect-uri"
    }

    override fun onApplicationEvent(event: ApplicationReadyEvent) = initialize(event.applicationContext.environment)

    override fun initialize(environment: Environment) {
        val clientId = environment.getRequiredProperty(CLIENT_ID_KEY)

        val client: OAuth2Client? = repository.findByClientId(OAuth2ClientId(clientId)).orElse(null)
        if (client == null) {
            val clientSecret = environment.getRequiredProperty(CLIENT_SECRET_KEY)
            val grantTypes = environment.getRequiredProperty(CLIENT_GRANT_TYPE_KEY).split(",")
                .map { AuthorizationGrantType(it) }
                .toMutableSet()
            val redirectUris = environment.getRequiredProperty(CLIENT_REDIRECT_URI).split(",")
                .map { URI.create(it) }
                .toMutableSet()

            val registerClient = OAuth2Client(clientId, clientSecret)
            registerClient.clientName = environment.getRequiredProperty(CLIENT_NAME)
            registerClient.owner = ClientOwner(environment.getRequiredProperty(USERNAME_KEY))
            registerClient.grantTypes = grantTypes
            registerClient.redirectUris = redirectUris
            registerClient.scopes = authorityDetailsService.loadInitializeAuthority()
                .map { AuthorityCode(it.code) }
                .toMutableSet()

            registerClient.encrypted(encoder)
            repository.save(registerClient)
        }
    }
}