package cube8540.oauth.authentication.credentials.oauth.client.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({
        "clientName", "newRedirectUris", "removeRedirectUri", "newGrantTypes", "removeGrantTypes", "newScopes", "removeScopes"
}))
@ApiModel(value = "OAuth2 클라이언트 수정 정보")
public class OAuth2ClientModifyRequest {

    @ApiModelProperty(value = "변경할 클라이언트명", required = true, example = "client-name")
    String clientName;

    @ApiModelProperty(value = "추가할 리다이렉트 URI 빈 배열 일시 리다이렉트 URI을 추가 하지 않습니다.", required = true, example = "[\"http://localhost:8082/callback\", \"http://localhost:8083/callback\"]")
    List<String> newRedirectUris;

    @ApiModelProperty(value = "삭제할 리다이렉트 URI 빈 배열 일시 리다이렉트 URI을 삭제 하지 않습니다.", required = true, example = "[\"http://localhost:8080/callback\", \"http://localhost:8081/callback\"]")
    List<String> removeRedirectUris;

    @ApiModelProperty(value = "추가할 인증 타입 빈 배열 일시 인증 타입을 추가 하지 않습니다.", required = true, example = "[\"authorization_code\", \"refresh_token\", \"client_credentials\"]")
    List<String> newGrantTypes;

    @ApiModelProperty(value = "삭제할 인증 타입 빈 배열 일시 인증 타입을 삭제 하지 않습니다.", required = true, example = "[\"authorization_code\", \"refresh_token\", \"client_credentials\"]")
    List<String> removeGrantTypes;

    @ApiModelProperty(value = "추가할 스코프 빈 배열 일시 스코프를 추가 하지 않습니다.", required = true, example = "[\"TEST-1\", \"TEST-2\"]")
    List<String> newScopes;

    @ApiModelProperty(value = "삭제할 스코프 빈 배열 일시 스코프를 삭제 하지 않습니다.", required = true, example = "[\"TEST-1\", \"TEST-2\"]")
    List<String> removeScopes;

}
