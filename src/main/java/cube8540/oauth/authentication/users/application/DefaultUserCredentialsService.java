package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.credentials.authority.application.BasicAuthorityService;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserRepository;

import java.util.List;

public class DefaultUserCredentialsService implements UserCredentialsService {

    private final UserRepository repository;

    private final BasicAuthorityService authorityService;

    private final UserCredentialsKeyGenerator keyGenerator;

    public DefaultUserCredentialsService(UserRepository repository, BasicAuthorityService authorityService, UserCredentialsKeyGenerator keyGenerator) {
        this.repository = repository;
        this.authorityService = authorityService;
        this.keyGenerator = keyGenerator;
    }

    @Override
    public UserProfile grantCredentialsKey(String email) {
        User user = repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> new UserNotFoundException(email + " user not found"));

        user.generateCredentialsKey(keyGenerator);
        return new UserProfile(repository.save(user));
    }

    @Override
    public UserProfile accountCredentials(String email, String credentialsKey) {
        User user = repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> new UserNotFoundException(email + " user not found"));
        List<AuthorityCode> authorityCodes = authorityService.getBasicAuthority();

        user.credentials(credentialsKey, authorityCodes);
        return new UserProfile(repository.save(user));
    }
}
