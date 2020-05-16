package cube8540.oauth.authentication.users.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"username", "email", "password"}))
public class UserRegisterRequest {

    private String username;

    private String email;

    private String password;

}
