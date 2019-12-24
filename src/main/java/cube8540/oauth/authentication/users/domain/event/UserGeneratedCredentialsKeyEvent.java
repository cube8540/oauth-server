package cube8540.oauth.authentication.users.domain.event;

import cube8540.oauth.authentication.users.domain.UserCredentialsKey;
import cube8540.oauth.authentication.users.domain.UserEmail;
import lombok.Value;

@Value
public class UserGeneratedCredentialsKeyEvent {

    private UserEmail email;

    private UserCredentialsKey key;

}
