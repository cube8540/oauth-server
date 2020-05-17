package cube8540.oauth.authentication.users.domain;

import lombok.Value;

@Value
public class UserGeneratedCredentialsKeyEvent {

    private Username username;

    private UserEmail email;

    private UserCredentialsKey key;

}
