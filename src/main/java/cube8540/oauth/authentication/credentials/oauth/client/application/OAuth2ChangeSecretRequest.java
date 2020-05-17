package cube8540.oauth.authentication.credentials.oauth.client.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"existsSecret", "newSecret"}))
@ApiModel(value = "OAuth2 클라이언트 패스워드 수정 정보")
public class OAuth2ChangeSecretRequest {

    @ApiModelProperty(value = "변경할 클라이언트의 기존에 사용하던 패스워드", required = true, example = "client-secret")
    String existsSecret;

    @ApiModelProperty(value = "변경할 클라이언트 패스워드", required = true, example = "new-client-secret")
    String newSecret;

}
