package cube8540.oauth.authentication.credentials.resource.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"resource", "method", "newAuthorities", "removeAuthorities"}))
@ApiModel(value = "보호 자원 수정 정보")
public class SecuredResourceModifyRequest {

    @ApiModelProperty(value = "수정할 자원 패턴", required = true, example = "/resource/**")
    String resource;

    @ApiModelProperty(value = "수정할 자원 메소드", required = true, example = "GET")
    String method;

    @ApiModelProperty(value = "추가할 접근 가능한 스코프 빈 배열일 시 스코프를 추가 하지 않습니다.", required = true, example = "[{\"authority\": \"ROLE_USER\", \"authorityType\": \"AUTHORITY\"}, {\"authority\": \"access.test\", \"authorityType\": \"SCOPE\"}]")
    List<AccessibleAuthorityValue> newAuthorities;

    @ApiModelProperty(value = "삭제할 접근 가능한 스코프 빈 배열일 시 스코프를 삭제 하지 않습니다.", required = true, example = "[{\"authority\": \"ROLE_USER\", \"authorityType\": \"AUTHORITY\"}, {\"authority\": \"access.test\", \"authorityType\": \"SCOPE\"}]")
    List<AccessibleAuthorityValue> removeAuthorities;

}
