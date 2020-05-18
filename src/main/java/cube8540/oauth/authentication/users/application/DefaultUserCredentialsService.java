package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.BasicAuthorityDetailsService;
import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserAuthority;
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

    private final BasicAuthorityDetailsService basicAuthorityDetailsService;

    @Setter
    private UserCredentialsKeyGenerator keyGenerator = new DefaultUserCredentialsKeyGenerator();

    public DefaultUserCredentialsService(UserRepository repository, BasicAuthorityDetailsService basicAuthorityDetailsService) {
        this.repository = repository;
        this.basicAuthorityDetailsService = basicAuthorityDetailsService;
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

        basicAuthorityDetailsService.loadBasicAuthorities().stream()
                .map(AuthorityDetails::getCode).map(UserAuthority::new)
                .forEach(user::grantAuthority);
        return UserProfile.of(repository.save(user));
    }

    private User getUser(String username) {
        return repository.findByUsername(new Username(username))
                .orElseThrow(() -> UserNotFoundException.instance(username + " is not found"));
    }
}
