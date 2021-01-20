package cube8540.oauth.authentication.credentials.oauth.security.provider

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import java.util.*

class ClientCredentialsToken(
    private val principal: Any?,

    private var credentials: Any?,

    authorities: Collection<GrantedAuthority>?
): AbstractAuthenticationToken(authorities) {

    init {
        if (authorities != null) {
            super.setAuthenticated(true)
        } else {
            super.setAuthenticated(false)
        }
    }

    constructor(principal: Any?, credentials: Any?): this(principal, credentials, null)

    override fun getPrincipal(): Any? = principal

    override fun getCredentials(): Any? = credentials

    override fun getName(): String = when (principal) {
        is String -> principal
        is OAuth2ClientDetails -> principal.clientId
        else -> super.getName()
    }

    override fun setAuthenticated(authenticated: Boolean) {
        throw IllegalArgumentException("this operation is not supported")
    }

    override fun eraseCredentials() {
        super.eraseCredentials()
        this.credentials = null
    }

    override fun equals(other: Any?): Boolean = when {
        other == null -> false
        other is ClientCredentialsToken -> {
            other.principal == this.principal &&
                    other.credentials == this.credentials &&
                    other.authorities == this.authorities
        }
        else -> false
    }

    override fun hashCode(): Int = Objects.hash(principal, credentials, authorities)
}