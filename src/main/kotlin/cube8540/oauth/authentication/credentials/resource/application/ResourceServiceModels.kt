package cube8540.oauth.authentication.credentials.resource.application

import cube8540.oauth.authentication.credentials.resource.domain.AccessibleAuthority
import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod
import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import java.beans.ConstructorProperties
import java.net.URI

@ApiModel(value = "접근 권한")
data class AccessibleAuthorityValue @ConstructorProperties(value = ["authority"]) constructor(
    @ApiModelProperty(value = "접근 권한 코드", required = true, example = "ROLE_USER")
    val authority: String
) {
    companion object {

        @JvmStatic fun of(authority: AccessibleAuthority) = AccessibleAuthorityValue(authority.authority)
    }
}

@ApiModel(value = "보호 자원 상세 정보")
interface SecuredResourceDetails {

    @get:ApiModelProperty(value = "보호 자원 아이디", required = true, example = "resource-id")
    val resourceId: String

    @get:ApiModelProperty(value = "보호 자원 패턴", required = true, example = "/resource/**")
    val resource: URI

    @get:ApiModelProperty(value = "보호 자원 메소드", required = true, example = "GET")
    val method: ResourceMethod

    @get:ApiModelProperty(value = "보호 자원 접근 가능 스코프", required = true, example = "[{\"authority\": \"ROLE_USER\", \"authorityType\": \"AUTHORITY\"}, {\"authority\": \"access.test\", \"authorityType\": \"SCOPE\"}]")
    val authorities: List<AccessibleAuthorityValue>

}