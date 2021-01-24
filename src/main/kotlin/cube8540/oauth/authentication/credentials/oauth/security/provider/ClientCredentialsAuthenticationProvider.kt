package cube8540.oauth.authentication.credentials.oauth.security.provider

import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ClientRegistrationException
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetailsService
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.InternalAuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.crypto.password.PasswordEncoder
import java.util.*

class ClientCredentialsAuthenticationProvider(private val service: OAuth2ClientDetailsService, private val encoder: PasswordEncoder): AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication {
        try {
            if (authentication.principal == null || authentication.credentials == null) {
                throw BadCredentialsException("Principal and credentials is required")
            }

            val client = service.loadClientDetailsByClientId(authentication.principal.toString())
            val givenSecret = authentication.credentials.toString()

            if (!encoder.matches(givenSecret, client.clientSecret)) {
                throw BadCredentialsException("Secret does not match stored value")
            }

            return ClientCredentialsToken(client, client.clientSecret, Collections.emptyList())
        } catch (e: OAuth2ClientRegistrationException) {
            throw BadCredentialsException(e.message)
        } catch (e: Exception) {
            when (e) {
                is BadCredentialsException,
                is InternalAuthenticationServiceException -> throw e
                else -> throw InternalAuthenticationServiceException(e.message, e)
            }
        }
    }

    override fun supports(authentication: Class<*>): Boolean =
        ClientCredentialsToken::class.java.isAssignableFrom(authentication)
}