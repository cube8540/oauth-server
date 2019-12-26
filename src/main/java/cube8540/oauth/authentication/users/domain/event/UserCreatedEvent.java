package cube8540.oauth.authentication.users.domain.event;

import cube8540.oauth.authentication.users.domain.UserEmail;
import lombok.Value;

@Value
public class UserCreatedEvent {

    private UserEmail email;

}
