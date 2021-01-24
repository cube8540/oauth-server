package cube8540.oauth.authentication.resource.application

import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import java.beans.ConstructorProperties

@ApiModel(value = "보호 자원 등록 정보")
data class SecuredResourceRegisterRequest @ConstructorProperties(value = [
    "resourceId",
    "resource",
    "method",
    "authorities"
]) constructor(
    @ApiModelProperty(value = "등록할 자원 아이디", required = true, example = "resource-id")
    val resourceId: String,

    @ApiModelProperty(value = "등록할 자원 패턴", required = true, example = "/resource/**")
    val resource: String,

    @ApiModelProperty(value = "등록할 자원 메소드", required = true, example = "GET")
    val method: String,

    @ApiModelProperty(value = "접근 가능한 스코프", required = true, example = "[{\"authority\": \"ROLE_USER\"}, {\"authority\": \"access.test\"}]")
    val authorities: List<AccessibleAuthorityValue>?
)

@ApiModel(value = "보호 자원 수정 정보")
data class SecuredResourceModifyRequest @ConstructorProperties(value = [
    "resource",
    "method",
    "newAuthorities",
    "removeAuthorities"
]) constructor(
    @ApiModelProperty(value = "수정할 자원 패턴", required = true, example = "/resource/**")
    val resource: String,

    @ApiModelProperty(value = "수정할 자원 메소드", required = true, example = "GET")
    val method: String,

    @ApiModelProperty(value = "추가할 접근 가능한 스코프 빈 배열일 시 스코프를 추가 하지 않습니다.", required = true, example = "[{\"authority\": \"ROLE_USER\"}, {\"authority\": \"access.test\"}]")
    val newAuthorities: List<AccessibleAuthorityValue>?,

    @ApiModelProperty(value = "삭제할 접근 가능한 스코프 빈 배열일 시 스코프를 삭제 하지 않습니다.", required = true, example = "[{\"authority\": \"ROLE_USER\"}, {\"authority\": \"access.test\"}]")
    val removeAuthorities: List<AccessibleAuthorityValue>?
)