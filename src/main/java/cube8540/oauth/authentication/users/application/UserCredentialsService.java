package cube8540.oauth.authentication.users.application;

public interface UserCredentialsService {

    UserProfile grantCredentialsKey(String email);

    UserProfile accountCredentials(String email, String credentialsKey);

}
