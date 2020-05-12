package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserRepository;
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
    public UserProfile grantCredentialsKey(String email) {
        User user = getUser(email);

        user.generateCredentialsKey(keyGenerator);
        return UserProfile.of(repository.save(user));
    }

    @Override
    @Transactional
    public UserProfile accountCredentials(String email, String credentialsKey) {
        User user = getUser(email);

        user.credentials(credentialsKey);
        return UserProfile.of(repository.save(user));
    }

    private User getUser(String email) {
        return repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> UserNotFoundException.instance(email + " is not found"));
    }
}
