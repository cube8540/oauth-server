package cube8540.oauth.authentication.users.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"email", "password"}))
public class UserRegisterRequest {

    private String email;

    private String password;

}
