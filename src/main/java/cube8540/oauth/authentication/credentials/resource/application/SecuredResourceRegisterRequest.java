package cube8540.oauth.authentication.credentials.resource.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"resourceId", "resource", "method", "authorities"}))
@ApiModel(value = "보호 자원 등록 정보")
public class SecuredResourceRegisterRequest {

    @ApiModelProperty(value = "등록할 자원 아이디", required = true, example = "resource-id")
    String resourceId;

    @ApiModelProperty(value = "등록할 자원 패턴", required = true, example = "/resource/**")
    String resource;

    @ApiModelProperty(value = "등록할 자원 메소드", required = true, example = "GET")
    String method;

    @ApiModelProperty(value = "접근 가능한 스코프", required = true, example = "[{\"authority\": \"ROLE_USER\"}, {\"authority\": \"access.test\"}]")
    List<AccessibleAuthorityValue> authorities;

}
