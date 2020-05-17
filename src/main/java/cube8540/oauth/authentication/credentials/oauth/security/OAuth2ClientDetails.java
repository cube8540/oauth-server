package cube8540.oauth.authentication.credentials.oauth.security;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Set;

@ApiModel(value = "OAuth2 클라이언트 상세 정보")
public interface OAuth2ClientDetails {

    @ApiModelProperty(value = "클라이언트 아이디", required = true, example = "client-id")
    String getClientId();

    @ApiModelProperty(value = "클라이언트 패스워드", required = true, example = "client-secret")
    String getClientSecret();

    @ApiModelProperty(value = "클라이언트명", required = true, example = "client name")
    String getClientName();

    @ApiModelProperty(value = "클라이언트 라디이렉트 URI", required = true, example = "[\"http://localhost:8082/callback\", \"http://localhost:8083/callback\"]")
    Set<URI> getRegisteredRedirectUris();

    @ApiModelProperty(value = "클라이언트 인증 타입", required = true, example = "[\"authorization_code\", \"refresh_token\", \"client_credentials\"]")
    Set<AuthorizationGrantType> getAuthorizedGrantTypes();

    @ApiModelProperty(value = "클라이언트 스코프", required = true, example = "[\"TEST-1\", \"TEST-2\"]")
    Set<String> getScopes();

    @ApiModelProperty(value = "클라이언트 소유자", required = true, example = "username1234")
    String getOwner();

    @ApiModelProperty(value = "클라이언트 엑세스 토큰 유효 시간", required = true, example = "600000000000")
    Integer getAccessTokenValiditySeconds();

    @ApiModelProperty(value = "클라이언트 리플래시 토큰 유효 시간", required = true, example = "7200000000000")
    Integer getRefreshTokenValiditySeconds();

}
