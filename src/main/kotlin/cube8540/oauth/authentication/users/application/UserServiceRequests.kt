package cube8540.oauth.authentication.users.application

import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import java.beans.ConstructorProperties

@ApiModel(value = "등록할 계정 정보")
data class UserRegisterRequest @ConstructorProperties(value = ["username", "password"]) constructor(

    @ApiModelProperty(value = "등록할 유저 아이디 영문과 숫자 조합 4 ~ 18 글자 사이의 문자만 가능 합니다.", required = true, example = "username1234")
    val username: String,

    @ApiModelProperty(value = "등록할 유저의 패스워드 대문자와 소문자, 숫자, 특수문자(#?!@$%^&*)를 포함한 12 ~ 30 글자 사이의 문자만 가능 합니다.", required = true, example = "Password1234!@#$")
    val password: String
)

@ApiModel(value = "패스워드 초기화 요청 정보")
data class ResetPasswordRequest @ConstructorProperties(value = [
    "username",
    "credentialsKey",
    "newPassword"
]) constructor(

    @ApiModelProperty(value = "패스워드를 초기화할 유저 아이디", required = true, example = "username1234")
    val username: String,

    @ApiModelProperty(value = "패스워드 초기화 키", required = true, example = "xxxxxxxxxx")
    val credentialsKey: String,

    @ApiModelProperty(value = "변경할 패스워드 대문자와 소문자, 숫자, 특수문자(#?!@$%^&*)를 포함한 12 ~ 30 글자 사이의 문자만 가능 합니다.", required = true, example = "NewPassword1234!@#$")
    val newPassword: String
)

@ApiModel(value = "변경할 패스워드 정보")
data class ChangePasswordRequest @ConstructorProperties(value = ["existingPassword", "newPassword"]) constructor(

    @ApiModelProperty(value = "기존에 사용 중이던 패스워드", required = true, example = "Password1234!@#$")
    val existingPassword: String,

    @ApiModelProperty(value = "변경할 패스워드 대문자와 소문자, 숫자, 특수문자(#?!@$%^&*)를 포함한 12 ~ 30 글자 사이의 문자만 가능 합니다.", required = true, example = "NewPassword1234!@#$")
    val newPassword: String
)