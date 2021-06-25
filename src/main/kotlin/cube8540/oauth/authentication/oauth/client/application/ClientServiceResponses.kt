package cube8540.oauth.authentication.oauth.client.application

import com.fasterxml.jackson.annotation.JsonIgnore
import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.security.AuthorityCode
import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import java.net.URI
import java.time.Duration
import org.springframework.security.core.CredentialsContainer
import org.springframework.security.oauth2.core.AuthorizationGrantType

@ApiModel(value = "OAuth2 클라이언트 엔트리")
data class OAuth2ClientEntry(
    @get:ApiModelProperty(value = "클라이언트 아이디", required = true, example = "client-id")
    val clientId: String,

    @get:ApiModelProperty(value = "클라이언트명", required = true, example = "client name")
    val clientName: String?,

    @get:ApiModelProperty(value = "클라이언트 소유자", required = true, example = "username1234")
    val owner: String?,

    @get:ApiModelProperty(value = "클라이언트 엑세스 토큰 유효 시간", required = true, example = "600000000000")
    val accessTokenValiditySeconds: Int?,

    @get:ApiModelProperty(value = "클라이언트 리플래시 토큰 유효 시간", required = true, example = "7200000000000")
    val refreshTokenValiditySeconds: Int?
) {
    companion object {
        @JvmStatic
        fun of(client: OAuth2Client): OAuth2ClientEntry = OAuth2ClientEntry(
            clientId = client.clientId.value,
            clientName = client.clientName,
            owner = client.owner?.value,
            accessTokenValiditySeconds =  (client.accessTokenValidity?.let(Duration::toSeconds) ?: 0L).toInt(),
            refreshTokenValiditySeconds = (client.refreshTokenValidity?.let(Duration::toSeconds) ?: 0L).toInt()
        )
    }
}

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
            val scopes = client.scopes?.map(AuthorityCode::value)?.toSet() ?: emptySet()
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