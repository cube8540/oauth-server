package cube8540.oauth.authentication.users.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"username", "password"}))
@ApiModel(value = "등록할 계정 정보")
public class UserRegisterRequest {

    @ApiModelProperty(value = "등록할 유저 아이디 영문과 숫자 조합 4 ~ 18 글자 사이의 문자만 가능 합니다.", required = true, example = "username1234")
    String username;

    @ApiModelProperty(value = "등록할 유저의 패스워드 대문자와 소문자, 숫자, 특수문자(#?!@$%^&*)를 포함한 12 ~ 30 글자 사이의 문자만 가능 합니다.", required = true, example = "Password1234!@#$")
    String password;

}
