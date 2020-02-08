package cube8540.oauth.authentication.users.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"email", "existingPassword", "newPassword"}))
public class ChangePasswordRequest {

    private String email;

    private String existingPassword;

    private String newPassword;

}
