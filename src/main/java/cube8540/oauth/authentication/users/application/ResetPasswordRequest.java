package cube8540.oauth.authentication.users.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"username", "credentialsKey", "newPassword"}))
@ApiModel(value = "패스워드 초기화 요청 정보")
public class ResetPasswordRequest {

    @ApiModelProperty(value = "패스워드를 초기화할 유저 아이디", required = true, example = "username1234")
    String username;

    @ApiModelProperty(value = "패스워드 초기화 키", required = true, example = "xxxxxxxxxx")
    String credentialsKey;

    @ApiModelProperty(value = "변경할 패스워드 대문자와 소문자, 숫자, 특수문자(#?!@$%^&*)를 포함한 12 ~ 30 글자 사이의 문자만 가능 합니다.", required = true, example = "NewPassword1234!@#$")
    String newPassword;

}
