package cube8540.oauth.authentication.users.application;

public interface UserPasswordService {

    UserProfile changePassword(ChangePasswordRequest changeRequest);

    UserProfile forgotPassword(String email);

    boolean validateCredentialsKey(String email, String credentialsKey);

    UserProfile resetPassword(ResetPasswordRequest resetRequest);

}
