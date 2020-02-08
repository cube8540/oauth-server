package cube8540.oauth.authentication.users.infra;

import cube8540.oauth.authentication.users.domain.UserCredentialsKey;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;

import java.util.UUID;

public class DefaultUserCredentialsKeyGenerator implements UserCredentialsKeyGenerator {
    @Override
    public UserCredentialsKey generateKey() {
        String uuid = UUID.randomUUID().toString().replace("-", "");
        return new UserCredentialsKey(uuid);
    }
}
