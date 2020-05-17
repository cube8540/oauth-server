package cube8540.oauth.authentication.credentials.oauth.scope.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"scopeId", "description", "accessibleAuthority"}))
@ApiModel(value = "등록할 스코프 정보")
public class OAuth2ScopeRegisterRequest {

    @ApiModelProperty(value = "등록할 스코프 아이디", required = true, example = "test.scope")
    String scopeId;

    @ApiModelProperty(value = "스코프 설명", required = true, example = "test scope")
    String description;

    @ApiModelProperty(value = "등록할 스코프를 관리 할 수 있는 스코프", required = true, example = "[\"test.scope\"]")
    List<String> accessibleAuthority;

}
