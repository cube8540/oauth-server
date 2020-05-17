package cube8540.oauth.authentication.credentials.oauth.security;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.time.LocalDateTime;

@ApiModel(value = "OAuth2 토큰 상세 정보")
public interface OAuth2TokenDetails {

    @ApiModelProperty(value = "OAuth2 토큰", required = true, example = "xxxxxxxxxx")
    String getTokenValue();

    @ApiModelProperty(value = "OAuth2 토큰 만료 시간", required = true, example = "2020-05-18T05:13:00")
    LocalDateTime getExpiration();

    @ApiModelProperty(value = "OAuth2 토큰 만료 여부", required = true, example = "false")
    boolean isExpired();

    @ApiModelProperty(value = "OAuth2 토큰 만료 까지 남은 시간", required = true, example = "599")
    long getExpiresIn();

}
