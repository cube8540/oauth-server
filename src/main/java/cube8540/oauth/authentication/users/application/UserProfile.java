package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;

@Data
@RequiredArgsConstructor
@ApiModel(value = "유저 계정 정보")
public class UserProfile {

    @ApiModelProperty(value = "유저 아이디", example = "username1234")
    private final String username;

    @ApiModelProperty(value = "유저 등록일", example = "2020-05-18T05:13:00")
    private final LocalDateTime registeredAt;

    @ApiModelProperty(value = "계정 인증키", example = "xxxxxxxxxxxxxx")
    private String credentialsKey;

    public static UserProfile of(User user) {
        return new UserProfile(user.getUsername().getValue(), user.getRegisteredAt());
    }
}
