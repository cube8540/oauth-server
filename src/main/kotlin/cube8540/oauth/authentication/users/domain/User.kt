package cube8540.oauth.authentication.users.domain

import org.hibernate.annotations.CreationTimestamp
import org.hibernate.annotations.DynamicInsert
import org.hibernate.annotations.DynamicUpdate
import org.hibernate.annotations.Fetch
import org.hibernate.annotations.FetchMode
import org.hibernate.annotations.UpdateTimestamp
import org.springframework.data.domain.AbstractAggregateRoot
import org.springframework.security.crypto.password.PasswordEncoder
import java.time.LocalDateTime
import java.util.*
import javax.persistence.AttributeOverride
import javax.persistence.AttributeOverrides
import javax.persistence.CollectionTable
import javax.persistence.Column
import javax.persistence.ElementCollection
import javax.persistence.Embedded
import javax.persistence.EmbeddedId
import javax.persistence.Entity
import javax.persistence.JoinColumn
import javax.persistence.Table

@Entity
@Table(name = "user")
@DynamicInsert
@DynamicUpdate
class User private constructor(
    @EmbeddedId
    @AttributeOverride(name = "value", column = Column(name = "username"))
    var username: Username,

    @Column(name = "password", length = 64, nullable = false)
    var password: String
): AbstractAggregateRoot<User>() {

    @Embedded
    @AttributeOverrides(
        AttributeOverride(name = "keyValue", column = Column(name = "credentials_key", length = 32)),
        AttributeOverride(name = "expiryDateTime", column = Column(name = "credentials_key_expiry_datetime"))
    )
    var credentialsKey: UserCredentialsKey? = null

    @Embedded
    @AttributeOverrides(
        AttributeOverride(name = "keyValue", column = Column(name = "password_credentials_key", length = 32)),
        AttributeOverride(name = "expiryDateTime", column = Column(name = "password_credentials_key_expiry_datetime"))
    )
    var passwordCredentialsKey: UserCredentialsKey?  = null

    @Column(name = "is_credentials", nullable = false)
    var credentialed: Boolean  = false

    @ElementCollection
    @CollectionTable(name = "user_approval_scopes", joinColumns = [JoinColumn(name = "username", nullable = false)])
    @AttributeOverrides(value = [
        AttributeOverride(name = "clientId", column = Column(name = "client_id", nullable = false, length = 32)),
        AttributeOverride(name = "scopeId", column = Column(name = "scope_id", nullable = false, length = 32))
    ])
    @Fetch(FetchMode.JOIN)
    var approvalAuthorities: MutableSet<ApprovalAuthority>? = null

    @CreationTimestamp
    @Column(name = "registered_at", nullable = false)
    var registeredAt: LocalDateTime? = LocalDateTime.now()

    @UpdateTimestamp
    @Column(name = "last_updated_at", nullable = false)
    var lastUpdatedAt: LocalDateTime? = LocalDateTime.now()

    constructor(username: String, password: String): this(Username(username), password) {
        super.registerEvent(UserRegisteredEvent(Username(username)))
    }

    fun validation(factory: UserValidatorFactory)
        = factory.createValidator(this).result.hasErrorThrows(UserInvalidException::instance)

    fun generateCredentialsKey(keyGenerator: UserCredentialsKeyGenerator) {
        if (credentialed) {
            throw UserAuthorizationException.alreadyCredentials("This account is already certification")
        }
        this.credentialsKey = keyGenerator.generateKey()
    }

    fun credentials(key: String) {
        if (this.credentialsKey == null) {
            throw UserAuthorizationException.invalidKey("Key is not matched")
        }
        assertMatchedResult(this.credentialsKey!!.matches(key))
        this.credentialsKey = null
        this.credentialed = true
    }

    fun changePassword(existsPassword: String, changePassword: String, encoder: PasswordEncoder) {
        if (!encoder.matches(existsPassword, this.password)) {
            throw UserAuthorizationException.invalidPassword("Existing password is not matched")
        }
        this.password = changePassword
    }

    fun forgotPassword(keyGenerator: UserCredentialsKeyGenerator) {
        this.passwordCredentialsKey = keyGenerator.generateKey()
    }

    fun resetPassword(passwordCredentialsKey: String, changePassword: String) {
        if (this.passwordCredentialsKey == null) {
            throw UserAuthorizationException.invalidKey("Key is not matched")
        }
        assertMatchedResult(this.passwordCredentialsKey!!.matches(passwordCredentialsKey))
        this.password = changePassword
        this.passwordCredentialsKey = null
    }

    fun encrypted(encoder: PasswordEncoder) {
        this.password = encoder.encode(this.password)
    }

    fun addApprovalAuthority(clientId: String, authority: String) {
        if (approvalAuthorities == null) {
            approvalAuthorities = HashSet()
        }
        approvalAuthorities!!.add(ApprovalAuthority(clientId, authority))
    }

    fun revokeApprovalAuthority(clientId: String, authority: String) {
        if (approvalAuthorities == null) {
            approvalAuthorities = HashSet()
        }
        approvalAuthorities!!.remove(ApprovalAuthority(clientId, authority))
    }

    private fun assertMatchedResult(result: UserKeyMatchedResult) {
        if (result == UserKeyMatchedResult.NOT_MATCHED) {
            throw UserAuthorizationException.invalidKey("Key is not matched")
        } else if (result == UserKeyMatchedResult.EXPIRED) {
            throw UserAuthorizationException.keyExpired("Key is expired")
        }
    }

    override fun equals(other: Any?): Boolean = when {
        other == null -> false
        other is User && other.username == this.username -> true
        else -> false
    }

    override fun hashCode(): Int = this.username.hashCode()

}