package cube8540.oauth.authentication.users.domain;

import lombok.Value;

@Value
public class UserGeneratedCredentialsKeyEvent {

    Username username;

    UserEmail email;

    UserCredentialsKey key;

}
