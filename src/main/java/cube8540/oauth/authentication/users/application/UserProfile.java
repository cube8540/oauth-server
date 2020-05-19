package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Value;

import java.time.LocalDateTime;

@Value
@ApiModel(value = "유저 계정 정보")
public class UserProfile {

    @ApiModelProperty(value = "유저 아이디", example = "username1234")
    String username;

    @ApiModelProperty(value = "유저 이메일", example = "email@email.com")
    String email;

    @ApiModelProperty(value = "유저 등록일", example = "2020-05-18T05:13:00")
    LocalDateTime registeredAt;

    public static UserProfile of(User user) {
        return new UserProfile(user.getUsername().getValue(), user.getEmail().getValue(), user.getRegisteredAt());
    }
}
