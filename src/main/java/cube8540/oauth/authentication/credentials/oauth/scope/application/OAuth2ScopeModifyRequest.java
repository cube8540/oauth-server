package cube8540.oauth.authentication.credentials.oauth.scope.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({
        "description", "removeAccessibleAuthority", "newAccessibleAuthority"
}))
@ApiModel(value = "스코프 수정 정보")
public class OAuth2ScopeModifyRequest {

    @ApiModelProperty(value = "수정할 스코프 설명", required = true, example = "change description")
    String description;

    @ApiModelProperty(value = "삭제할 관리 가능 스코프 스코프 빈 배열 일시 스코프를 삭제 하지 않습니다.", required = true, example = "[\"test.scope\"]")
    List<String> removeAccessibleAuthority;

    @ApiModelProperty(value = "추가할 관리 가능 스코프 스코프 빈 배열 일시 스코프를 추가 하지 않습니다.", required = true, example = "[\"test.scope\"]")
    List<String> newAccessibleAuthority;

}
