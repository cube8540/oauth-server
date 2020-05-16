package cube8540.oauth.authentication.users.application;

public interface UserCredentialsService {

    UserProfile grantCredentialsKey(String username);

    UserProfile accountCredentials(String username, String credentialsKey);

}
