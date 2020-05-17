package cube8540.oauth.authentication.credentials.oauth.security;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

@ApiModel(value = "OAuth2 스코프 상세 정보")
public interface OAuth2ScopeDetails {

    @ApiModelProperty(value = "스코프 아이디", required = true, example = "test.scope")
    String getScopeId();

    @ApiModelProperty(value = "스코프 설명", required = true, example = "test scope")
    String getDescription();

}
