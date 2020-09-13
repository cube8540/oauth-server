package cube8540.oauth.authentication.credentials.oauth.client.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"clientId", "secret", "clientName", "redirectUris", "scopes", "grantTypes"}))
@ApiModel(value = "OAuth2 클라이언트 등록 정보")
public class OAuth2ClientRegisterRequest {

    @ApiModelProperty(value = "등록할 클라이언트 아이디", required = true, example = "client-id")
    String clientId;

    @ApiModelProperty(value = "등록할 클라이언트 패스워드", required = true, example = "client-secret")
    String secret;

    @ApiModelProperty(value = "등록할 클라이언트명", required = true, example = "client name")
    String clientName;

    @ApiModelProperty(value = "Authorization Code 인증에서 사용할 리다이렉트 URI", required = true, example = "[\"http://localhost:8080/callback\", \"http://localhost:8081/callback\"]")
    List<String> redirectUris;

    @ApiModelProperty(value = "이 클라이언트로 부여 받을 수 있는 스코프", required = true, example = "[\"TEST-1\", \"TEST-2\", \"TEST-3\"]")
    List<String> scopes;

    @ApiModelProperty(value = "클라이언트가 제공하는 인증 방식", required = true, example = "[\"authorization_code\", \"refresh_token\", \"client_credentials\"]")
    List<String> grantTypes;

    @ApiModelProperty(value = "엑세스 토큰 유효 기간 (초)", example = "60")
    Integer accessTokenValiditySeconds;

    @ApiModelProperty(value = "리플레시 토큰 유효 기간 (초)", example = "600")
    Integer refreshTokenValiditySeconds;

    @ApiModelProperty(value = "클라이언트 소유자", required = true, example = "username1234")
    String clientOwner;

}
