package cube8540.oauth.authentication.resource.application

import cube8540.oauth.authentication.resource.domain.ResourceMethod
import cube8540.oauth.authentication.resource.domain.SecuredResource
import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import java.net.URI

@ApiModel(value = "보호 자원 엔트리")
data class SecuredResourceEntry(
    @get:ApiModelProperty(value = "보호 자원 아이디", required = true, example = "resource-id")
    val resourceId: String,

    @get:ApiModelProperty(value = "보호 자원 패턴", required = true, example = "/resource/**")
    val resource: URI,

    @get:ApiModelProperty(value = "보호 자원 메소드", required = true, example = "GET")
    val method: ResourceMethod
) {
    companion object {
        @JvmStatic
        fun of(resource: SecuredResource) = SecuredResourceEntry(
            resourceId = resource.resourceId.value,
            resource = resource.resource,
            method = resource.method
        )
    }
}

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
                ?: emptyList()

            return DefaultSecuredResourceDetails(resource.resourceId.value, resource.resource, resource.method, authorities)
        }
    }
}