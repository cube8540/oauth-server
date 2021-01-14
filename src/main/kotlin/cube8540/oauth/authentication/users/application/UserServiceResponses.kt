package cube8540.oauth.authentication.users.application

import cube8540.oauth.authentication.users.domain.User
import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import java.time.LocalDateTime

@ApiModel(value = "유저 계정 등록 정보")
data class RegisteredUserProfile(

    @ApiModelProperty(value = "유저 아이디", example = "username1234")
    val username: String,

    @ApiModelProperty(value = "유저 등록일", example = "2020-05-18T05:13:00")
    val registeredAt: LocalDateTime?,

    @ApiModelProperty(value = "계정 인증키", example = "xxxxxxxxxxxxxx")
    val credentialsKey: String?
) {
    constructor(user: User): this(user.username.value, user.registeredAt, user.credentialsKey?.keyValue)
}

@ApiModel(value = "유저 계정 정보")
data class UserProfile(

    @ApiModelProperty(value = "유저 아이디", example = "username1234")
    val username: String,

    @ApiModelProperty(value = "유저 등록일", example = "2020-05-18T05:13:00")
    val registeredAt: LocalDateTime?
) {
    constructor(user: User): this(user.username.value, user.registeredAt)
}