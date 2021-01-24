package cube8540.oauth.authentication.credentials.oauth.token.domain

import cube8540.oauth.authentication.AuthenticationApplication
import cube8540.oauth.authentication.credentials.AuthorityCode
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.credentials.oauth.converter.RedirectUriConverter
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException.Companion.invalidClient
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException.Companion.invalidGrant
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException
import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest
import org.springframework.data.domain.AbstractAggregateRoot
import java.net.URI
import java.time.Clock
import java.time.LocalDateTime
import java.util.stream.Collectors
import javax.persistence.AttributeOverride
import javax.persistence.CollectionTable
import javax.persistence.Column
import javax.persistence.Convert
import javax.persistence.ElementCollection
import javax.persistence.Embedded
import javax.persistence.Entity
import javax.persistence.Id
import javax.persistence.JoinColumn
import javax.persistence.Table
import javax.persistence.Transient

@Entity
@Table(name = "oauth2_authorization_code")
class OAuth2AuthorizationCode(
    @Transient
    private val generator: AuthorizationCodeGenerator
): AbstractAggregateRoot<OAuth2AuthorizationCode>() {

    companion object {
        @JvmStatic
        @Transient
        protected var clock: Clock = AuthenticationApplication.DEFAULT_CLOCK
    }

    @Id
    @Column(name = "authorization_code", length = 6)
    var code: String = generator.generate()

    @Column(name = "expiration_at", nullable = false)
    var expirationDateTime: LocalDateTime? = LocalDateTime.now(clock).plusMinutes(5)

    @Embedded
    @AttributeOverride(name = "value", column = Column(name = "client_id", length = 32, nullable = false))
    var clientId: OAuth2ClientId? = null

    @Embedded
    @AttributeOverride(name = "value", column = Column(name = "username", length = 32, nullable = false))
    var username: PrincipalUsername? = null

    @Column(name = "state", length = 12)
    var state: String? = null

    @Column(name = "redirect_uri", length = 128)
    @Convert(converter = RedirectUriConverter::class)
    var redirectURI: URI? = null

    @ElementCollection
    @CollectionTable(name = "oauth2_code_approved_scope", joinColumns = [JoinColumn(name = "authorization_code", nullable = false)])
    @AttributeOverride(name = "value", column = Column(name = "scope_id", length = 32, nullable = false))
    var approvedScopes: MutableSet<AuthorityCode>? = null

    fun setAuthorizationRequest(request: AuthorizationRequest) {
        this.clientId = request.clientId?.let { client -> OAuth2ClientId(client) }
        this.username = request.username?.let { username -> PrincipalUsername(username) }
        this.redirectURI = request.redirectUri
        this.approvedScopes = request.requestScopes?.stream()
            ?.map { scope -> AuthorityCode(scope) }
            ?.collect(Collectors.toSet())
    }

    fun validateWithAuthorizationRequest(request: AuthorizationRequest) {
        if (expirationDateTime?.isBefore(LocalDateTime.now(clock)) == true) {
            throw invalidGrant("Authorization code is expired")
        }

        if ((redirectURI == null && request.redirectUri != null) ||
            (redirectURI != null && redirectURI != request.redirectUri)) {
            throw RedirectMismatchException("Redirect URI mismatched")
        }

        if (clientId != request.clientId?.let { id -> OAuth2ClientId(id) }) {
            throw invalidClient("Client id mismatch")
        }
    }

    override fun equals(other: Any?): Boolean = when {
        other == null -> false
        other is OAuth2AuthorizationCode && other.code == this.code -> true
        else -> false
    }

    override fun hashCode(): Int = code.hashCode()
}