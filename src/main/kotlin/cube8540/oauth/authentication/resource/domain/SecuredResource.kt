package cube8540.oauth.authentication.resource.domain

import java.net.URI
import javax.persistence.AttributeOverride
import javax.persistence.CollectionTable
import javax.persistence.Column
import javax.persistence.Convert
import javax.persistence.ElementCollection
import javax.persistence.EmbeddedId
import javax.persistence.Entity
import javax.persistence.EnumType
import javax.persistence.Enumerated
import javax.persistence.JoinColumn
import javax.persistence.Table
import org.springframework.data.domain.AbstractAggregateRoot

@Entity
@Table(name = "secured_resource")
class SecuredResource(
    @EmbeddedId
    @AttributeOverride(name = "value", column = Column(name = "resource_id", length = 32))
    var resourceId: SecuredResourceId,

    @Convert(converter = ResourceConverter::class)
    @Column(name = "resource", length = 128, nullable = false)
    var resource: URI,

    @Enumerated(EnumType.STRING)
    @Column(name = "method", length = 32, nullable = false)
    var method: ResourceMethod
): AbstractAggregateRoot<SecuredResource>() {

    @ElementCollection
    @AttributeOverride(name = "authority", column = Column(name = "authority", length = 32, nullable = false))
    @CollectionTable(name = "authority_accessible_resources", joinColumns = [JoinColumn(name = "resource_id", nullable = false)])
    var authorities: MutableSet<AccessibleAuthority>? = null

    fun changeResourceInfo(changeResource: URI, changeMethod: ResourceMethod) {
        this.resource = changeResource
        this.method = changeMethod

        registerSecuredResourceChangedEvent()
    }

    fun addAuthority(code: String) {
        if (authorities == null) {
            authorities = HashSet()
        }
        authorities!!.add(AccessibleAuthority(code))

        registerSecuredResourceChangedEvent()
    }

    fun removeAuthority(code: String) {
        if (authorities != null) {
            authorities!!.remove(AccessibleAuthority(code))
            registerSecuredResourceChangedEvent()
        }
    }

    fun validation(factory: SecuredResourceValidatorFactory) =
        factory.createValidator(this).result.hasErrorThrows(ResourceInvalidException::instance)

    private fun registerSecuredResourceChangedEvent() {
        val event = SecuredResourceChangedEvent(resourceId)

        if (!domainEvents().contains(event)) {
            registerEvent(event)
        }
    }

    override fun equals(other: Any?): Boolean = when {
        other == null -> false
        other is SecuredResource && other.resourceId == this.resourceId -> true
        else -> false
    }

    override fun hashCode(): Int = this.resourceId.hashCode()
}