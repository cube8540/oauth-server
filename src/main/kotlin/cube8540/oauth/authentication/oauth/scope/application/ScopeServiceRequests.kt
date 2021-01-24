package cube8540.oauth.authentication.oauth.scope.application

import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import java.beans.ConstructorProperties

@ApiModel(value = "등록할 스코프 정보")
data class OAuth2ScopeRegisterRequest @ConstructorProperties(value = ["scopeId", "description"]) constructor(

    @ApiModelProperty(value = "등록할 스코프 아이디", required = true, example = "test.scope")
    val scopeId: String,

    @ApiModelProperty(value = "스코프 설명", required = true, example = "test scope")
    val description: String
)

@ApiModel(value = "스코프 수정 정보")
data class OAuth2ScopeModifyRequest @ConstructorProperties(value = ["description"]) constructor(

    @ApiModelProperty(value = "수정할 스코프 설명", required = true, example = "change description")
    val description: String
)