package cube8540.oauth.authentication.users.domain;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Value;

@Value
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public class UserRegisterEvent {

    private UserEmail email;

}
