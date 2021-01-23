package cube8540.oauth.authentication.credentials.oauth.client.domain

import cube8540.oauth.authentication.credentials.AuthorityCode
import cube8540.oauth.authentication.credentials.oauth.converter.AuthorizationGrantTypeConverter
import cube8540.oauth.authentication.credentials.oauth.converter.RedirectUriConverter
import org.hibernate.annotations.Fetch
import org.hibernate.annotations.FetchMode
import org.springframework.data.domain.AbstractAggregateRoot
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import java.net.URI
import java.time.Duration
import javax.persistence.AttributeOverride
import javax.persistence.CollectionTable
import javax.persistence.Column
import javax.persistence.Convert
import javax.persistence.ElementCollection
import javax.persistence.Embedded
import javax.persistence.EmbeddedId
import javax.persistence.Entity
import javax.persistence.JoinColumn
import javax.persistence.Table

@Entity
@Table(name = "oauth2_clients")
class OAuth2Client(
    @EmbeddedId
    @AttributeOverride(name = "value", column = Column(name = "client_id", length = 32))
    var clientId: OAuth2ClientId,

    @Column(name = "client_secret", length = 64, nullable = false)
    var secret: String
): AbstractAggregateRoot<OAuth2Client>() {

    companion object {
        private val DEFAULT_ACCESS_TOKEN_VALIDITY = Duration.ofMinutes(10)
        private val DEFAULT_REFRESH_TOKEN_VALIDITY = Duration.ofHours(2)
    }

    @Column(name = "client_name", length = 32, nullable = false)
    var clientName: String? = null

    @ElementCollection
    @CollectionTable(name = "oauth2_client_redirect_uri", joinColumns = [JoinColumn(name = "client_id", nullable = false)])
    @Column(name = "redirect_uri", length = 128, nullable = false)
    @Convert(converter = RedirectUriConverter::class)
    @Fetch(FetchMode.JOIN)
    var redirectUris: MutableSet<URI>? = null

    @ElementCollection
    @CollectionTable(name = "oauth2_client_grant_type", joinColumns = [JoinColumn(name = "client_id", nullable = false)])
    @Column(name = "grant_type", length = 32, nullable = false)
    @Convert(converter = AuthorizationGrantTypeConverter::class)
    @Fetch(FetchMode.JOIN)
    var grantTypes: MutableSet<AuthorizationGrantType>? = null

    @ElementCollection
    @CollectionTable(name = "oauth2_client_scope", joinColumns = [JoinColumn(name = "client_id", nullable = false)])
    @AttributeOverride(name = "value", column = Column(name = "scope_id", length = 32, nullable = false))
    @Fetch(FetchMode.JOIN)
    var scopes: MutableSet<AuthorityCode>? = null

    @Embedded
    @AttributeOverride(name = "value", column = Column(name = "oauth2_client_owner", nullable = false, length = 128))
    var owner: ClientOwner? = null

    @Column(name = "access_token_validity", nullable = false)
    var accessTokenValidity: Duration? = DEFAULT_ACCESS_TOKEN_VALIDITY

    @Column(name = "refresh_token_validity", nullable = false)
    var refreshTokenValidity: Duration? = DEFAULT_REFRESH_TOKEN_VALIDITY

    constructor(clientId: String, secret: String): this(OAuth2ClientId(clientId), secret)

    fun encrypted(encoder: PasswordEncoder) {
        this.secret = encoder.encode(this.secret)
    }

    fun addRedirectUri(uri: URI) {
        if (this.redirectUris == null) {
            this.redirectUris = HashSet()
        }
        this.redirectUris!!.add(uri)
    }

    fun removeRedirectUri(redirectUri: URI) {
        if (this.redirectUris != null) {
            this.redirectUris!!.remove(redirectUri)
        }
    }

    fun addGrantType(grantType: AuthorizationGrantType) {
        if (this.grantTypes == null) {
            this.grantTypes = HashSet()
        }
        this.grantTypes!!.add(grantType)
    }

    fun removeGrantType(grantType: AuthorizationGrantType) {
        if (this.grantTypes != null) {
            this.grantTypes!!.remove(grantType)
        }
    }

    fun addScope(scope: AuthorityCode) {
        if (this.scopes == null) {
            this.scopes = HashSet()
        }
        this.scopes!!.add(scope)
    }

    fun removeScope(scope: AuthorityCode) {
        if (this.scopes != null) {
            this.scopes!!.remove(scope)
        }
    }

    fun setAccessTokenValidity(validity: Int) {
        this.accessTokenValidity = Duration.ofSeconds(validity.toLong())
    }

    fun setRefreshTokenValidity(validity: Int) {
        this.refreshTokenValidity = Duration.ofSeconds(validity.toLong())
    }

    fun validate(factory: OAuth2ClientValidatorFactory) =
        factory.createValidator(this).result.hasErrorThrows { errors -> ClientInvalidException.instance(errors) }

    fun changeSecret(existsSecret: String, changeSecret: String, encoder: PasswordEncoder) {
        if (!encoder.matches(existsSecret, secret)) {
            throw ClientAuthorizationException.invalidPassword("Exists secret is not matches")
        }
        this.secret = changeSecret
    }

    override fun equals(other: Any?): Boolean = when {
        other == null -> false
        other is OAuth2Client && other.clientId == this.clientId -> true
        else -> false
    }

    override fun hashCode(): Int = clientId.hashCode()
}