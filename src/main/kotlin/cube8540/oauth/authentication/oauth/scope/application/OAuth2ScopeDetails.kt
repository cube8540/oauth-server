package cube8540.oauth.authentication.oauth.scope.application

import cube8540.oauth.authentication.oauth.scope.domain.OAuth2Scope
import cube8540.oauth.authentication.security.AuthorityDetails
import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty

@ApiModel(value = "스코프 정보")
data class OAuth2ScopeDetails(
    @get:ApiModelProperty(value = "권한 코드", required = true, example = "AUTH_USER")
    override val code: String,

    @get:ApiModelProperty(value = "권한 설명", required = true, example = "Default User Authority")
    val description: String
): AuthorityDetails {
    companion object {
        fun of(scope: OAuth2Scope): OAuth2ScopeDetails = OAuth2ScopeDetails(scope.code.value, scope.description)
    }
}
