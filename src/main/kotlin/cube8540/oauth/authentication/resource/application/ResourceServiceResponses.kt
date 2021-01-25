package cube8540.oauth.authentication.resource.application

import cube8540.oauth.authentication.resource.domain.ResourceMethod
import cube8540.oauth.authentication.resource.domain.SecuredResource
import java.net.URI
import java.util.*
import java.util.stream.Collectors

data class DefaultSecuredResourceDetails(
    override val resourceId: String,

    override val resource: URI,

    override val method: ResourceMethod,

    override val authorities: List<AccessibleAuthorityValue>
): SecuredResourceDetails {
    companion object {
        @JvmStatic
        fun of(resource: SecuredResource): DefaultSecuredResourceDetails {
            val authorities = resource.authorities
                ?.map { AccessibleAuthorityValue(it.authority) }?.toList()
                ?: Collections.emptyList()

            return DefaultSecuredResourceDetails(resource.resourceId.value, resource.resource, resource.method, authorities)
        }
    }
}