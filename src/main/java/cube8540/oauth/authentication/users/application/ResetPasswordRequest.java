package cube8540.oauth.authentication.users.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"username", "credentialsKey", "newPassword"}))
public class ResetPasswordRequest {

    private String username;

    private String credentialsKey;

    private String newPassword;

}
