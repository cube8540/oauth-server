package cube8540.oauth.authentication.users.application

import cube8540.oauth.authentication.oauth.security.SecurityUserDetails
import cube8540.oauth.authentication.users.domain.User
import org.springframework.security.core.CredentialsContainer
import org.springframework.security.core.GrantedAuthority

class SecurityUser(
    private val username: String,
    private var password: String?,
    private val authorities: MutableCollection<out GrantedAuthority> = mutableListOf(),
    private val accountNonExpired: Boolean = true,
    private val accountNonLocked: Boolean = true,
    private val credentialsNonExpired: Boolean = true,
    private val enabled: Boolean = true,
    override val uid: String,
): SecurityUserDetails, CredentialsContainer {

    companion object {
        @JvmStatic
        fun of(user: User): SecurityUser = SecurityUser(
            username = user.username.value,
            password = user.password,
            uid = user.uid.value,
            accountNonLocked = (user.credentialed),
        )
    }

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = authorities

    override fun getPassword(): String? = password

    override fun getUsername(): String = username

    override fun isAccountNonExpired(): Boolean = accountNonExpired

    override fun isAccountNonLocked(): Boolean = accountNonLocked

    override fun isCredentialsNonExpired(): Boolean = credentialsNonExpired

    override fun isEnabled(): Boolean = enabled

    override fun eraseCredentials() {
        this.password = null
    }

    override fun equals(other: Any?): Boolean = when {
        other == null -> false
        other is SecurityUser && other.username == this.username -> true
        else -> false
    }

    override fun hashCode(): Int = username.hashCode()
}