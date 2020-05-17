package cube8540.oauth.authentication.credentials.oauth.token.domain.read.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.time.LocalDateTime;
import java.util.Map;

@ApiModel(value = "엑세스 토큰 및 클라이언트 정보")
public interface AccessTokenDetailsWithClient {

    @ApiModelProperty(value = "OAuth2 엑세스 토큰", required = true, example = "xxxxxxxxxxx")
    String getTokenValue();

    AccessTokenClient getClient();

    @ApiModelProperty(value = "OAuth2 엑세스 토큰 소유자", required = true, example = "username1234")
    String getUsername();

    @ApiModelProperty(value = "OAuth2 엑세스 토큰 발행 시간", required = true, example = "2020-05-18T05:13:00")
    LocalDateTime getIssuedAt();

    @ApiModelProperty(value = "OAuth2 엑세스 토큰 만료 까지 남은 시간", required = true, example = "599")
    long getExpiresIn();

    @ApiModelProperty(value = "OAuth2 엑세스 토큰 추가 정보")
    Map<String, String> getAdditionalInformation();

    @ApiModel(value = "엑세스 토큰 클라이언트 정보")
    interface AccessTokenClient {

        @ApiModelProperty(value = "클라이언트 아이디")
        String getClientId();

        @ApiModelProperty(value = "클라이언트명")
        String getClientName();
    }
}
