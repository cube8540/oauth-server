package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.credentials.authority.application.BasicAuthorityService;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.error.UserNotFoundException;
import cube8540.oauth.authentication.users.infra.DefaultUserCredentialsKeyGenerator;
import lombok.Setter;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class DefaultUserCredentialsService implements UserCredentialsService {

    private final UserRepository repository;

    private final BasicAuthorityService authorityService;

    @Setter
    private UserCredentialsKeyGenerator keyGenerator = new DefaultUserCredentialsKeyGenerator();

    public DefaultUserCredentialsService(UserRepository repository, BasicAuthorityService authorityService) {
        this.repository = repository;
        this.authorityService = authorityService;
    }

    @Override
    @Transactional
    public UserProfile grantCredentialsKey(String email) {
        User user = repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> new UserNotFoundException(email + " user not found"));

        user.generateCredentialsKey(keyGenerator);
        return UserProfile.of(repository.save(user));
    }

    @Override
    @Transactional
    public UserProfile accountCredentials(String email, String credentialsKey) {
        User user = repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> new UserNotFoundException(email + " user not found"));
        List<AuthorityCode> authorityCodes = authorityService.getBasicAuthority();

        user.credentials(credentialsKey, authorityCodes);
        return UserProfile.of(repository.save(user));
    }
}
