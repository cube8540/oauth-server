package cube8540.oauth.authentication.users.application;

public interface UserPasswordService {

    UserProfile changePassword(String username, ChangePasswordRequest changeRequest);

    UserProfile forgotPassword(String username);

    boolean validateCredentialsKey(String username, String credentialsKey);

    UserProfile resetPassword(ResetPasswordRequest resetRequest);

}
