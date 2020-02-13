package cube8540.oauth.authentication.users.application;

import java.security.Principal;

public interface UserPasswordService {

    UserProfile changePassword(Principal principal, ChangePasswordRequest changeRequest);

    UserProfile forgotPassword(String email);

    boolean validateCredentialsKey(String email, String credentialsKey);

    UserProfile resetPassword(ResetPasswordRequest resetRequest);

}
