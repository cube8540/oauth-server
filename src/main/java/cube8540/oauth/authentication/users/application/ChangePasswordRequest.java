package cube8540.oauth.authentication.users.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"existingPassword", "newPassword"}))
@ApiModel(value = "변경할 패스워드 정보")
public class ChangePasswordRequest {

    @ApiModelProperty(value = "기존에 사용 중이던 패스워드", required = true, example = "Password1234!@#$")
    String existingPassword;

    @ApiModelProperty(value = "변경할 패스워드 대문자와 소문자, 숫자, 특수문자(#?!@$%^&*)를 포함한 12 ~ 30 글자 사이의 문자만 가능 합니다.", required = true, example = "NewPassword1234!@#$")
    String newPassword;

}
