package cube8540.oauth.authentication.oauth.scope.domain

import cube8540.oauth.authentication.security.AuthorityCode
import org.springframework.data.domain.AbstractAggregateRoot
import javax.persistence.AttributeOverride
import javax.persistence.Column
import javax.persistence.EmbeddedId
import javax.persistence.Entity
import javax.persistence.Table

@Entity
@Table(name = "oauth2_scope")
class OAuth2Scope private constructor(

    @EmbeddedId
    @AttributeOverride(name = "value", column = Column(name = "scope_id", length = 32))
    var code: AuthorityCode,

    @Column(name = "description", length = 32)
    var description: String
): AbstractAggregateRoot<OAuth2Scope>() {

    constructor(scopeId: String, description: String): this(AuthorityCode(scopeId), description)

    override fun equals(other: Any?): Boolean = when {
        other == null -> false
        other is OAuth2Scope && other.code == this.code -> true
        else -> false
    }

    override fun hashCode(): Int = code.hashCode()
}