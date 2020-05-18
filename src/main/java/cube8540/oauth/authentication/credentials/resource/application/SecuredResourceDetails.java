package cube8540.oauth.authentication.credentials.resource.application;

import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.net.URI;
import java.util.List;

@ApiModel(value = "보호 자원 상세 정보")
public interface SecuredResourceDetails {

    @ApiModelProperty(value = "보호 자원 아이디", required = true, example = "resource-id")
    String getResourceId();

    @ApiModelProperty(value = "보호 자원 패턴", required = true, example = "/resource/**")
    URI getResource();

    @ApiModelProperty(value = "보호 자원 메소드", required = true, example = "GET")
    ResourceMethod getMethod();

    @ApiModelProperty(value = "보호 자원 접근 가능 스코프", required = true, example = "[\"test.scope0\", \"test.scope1\"]")
    List<String> getAuthorities();

}
