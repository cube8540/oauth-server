package cube8540.oauth.authentication.users.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"email", "credentialsKey", "newPassword"}))
public class ResetPasswordRequest {

    private String email;

    private String credentialsKey;

    private String newPassword;

}
