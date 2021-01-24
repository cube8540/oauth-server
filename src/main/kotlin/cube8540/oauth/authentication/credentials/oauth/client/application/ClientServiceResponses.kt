package cube8540.oauth.authentication.credentials.oauth.client.application

import com.fasterxml.jackson.annotation.JsonIgnore
import cube8540.oauth.authentication.credentials.AuthorityCode
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails
import org.springframework.security.core.CredentialsContainer
import org.springframework.security.oauth2.core.AuthorizationGrantType
import java.net.URI
import java.time.Duration
import java.util.*

data class DefaultOAuth2ClientDetails(
    override val clientId: String,

    @JsonIgnore
    override var clientSecret: String?,

    override val clientName: String?,

    override val registeredRedirectUris: Set<URI>?,

    override val authorizedGrantTypes: Set<AuthorizationGrantType>?,

    override val scopes: Set<String>,

    override val owner: String?,

    override val accessTokenValiditySeconds: Int?,

    override val refreshTokenValiditySeconds: Int?
): OAuth2ClientDetails, CredentialsContainer {

    companion object {
        @JvmStatic
        fun of(client: OAuth2Client): DefaultOAuth2ClientDetails {
            val scopes = client.scopes?.map(AuthorityCode::value)?.toSet() ?: Collections.emptySet()
            val tokenValidity = client.accessTokenValidity?.let(Duration::toSeconds) ?: 0L
            val refreshValidity = client.refreshTokenValidity?.let(Duration::toSeconds) ?: 0L

            return DefaultOAuth2ClientDetails(
                clientId = client.clientId.value,
                clientSecret = client.secret,
                clientName = client.clientName,
                registeredRedirectUris = client.redirectUris,
                authorizedGrantTypes = client.grantTypes,
                scopes = scopes,
                owner = client.owner?.value,
                accessTokenValiditySeconds = tokenValidity.toInt(),
                refreshTokenValiditySeconds = refreshValidity.toInt()
            )
        }
    }

    override fun eraseCredentials() {
        this.clientSecret = null
    }

}