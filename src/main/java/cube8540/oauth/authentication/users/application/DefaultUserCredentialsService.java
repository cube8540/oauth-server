package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.Username;
import cube8540.oauth.authentication.users.domain.exception.UserNotFoundException;
import cube8540.oauth.authentication.users.infra.DefaultUserCredentialsKeyGenerator;
import lombok.Setter;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DefaultUserCredentialsService implements UserCredentialsService {

    private final UserRepository repository;

    @Setter
    private UserCredentialsKeyGenerator keyGenerator = new DefaultUserCredentialsKeyGenerator();

    public DefaultUserCredentialsService(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    @Transactional
    public UserProfile grantCredentialsKey(String username) {
        User user = getUser(username);

        user.generateCredentialsKey(keyGenerator);
        return UserProfile.of(repository.save(user));
    }

    @Override
    @Transactional
    public UserProfile accountCredentials(String username, String credentialsKey) {
        User user = getUser(username);

        user.credentials(credentialsKey);
        return UserProfile.of(repository.save(user));
    }

    private User getUser(String username) {
        return repository.findByUsername(new Username(username))
                .orElseThrow(() -> UserNotFoundException.instance(username + " is not found"));
    }
}
