package cube8540.oauth.authentication.credentials.oauth.scope.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"description", "secured"}))
@ApiModel(value = "스코프 수정 정보")
public class OAuth2ScopeModifyRequest {

    @ApiModelProperty(value = "수정할 스코프 설명", required = true, example = "change description")
    String description;

    @ApiModelProperty(value = "수정할 스코프 보호 여부", required = true, example = "true")
    Boolean secured;

}
