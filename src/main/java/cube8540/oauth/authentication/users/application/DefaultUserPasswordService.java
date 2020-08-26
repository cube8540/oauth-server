package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserKeyMatchedResult;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidatorFactory;
import cube8540.oauth.authentication.users.domain.Username;
import cube8540.oauth.authentication.users.domain.exception.UserNotFoundException;
import cube8540.oauth.authentication.users.infra.DefaultUserCredentialsKeyGenerator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;

@Service
public class DefaultUserPasswordService implements UserPasswordService {

    private final UserRepository repository;

    private final PasswordEncoder encoder;

    @Setter
    private UserCredentialsKeyGenerator keyGenerator = new DefaultUserCredentialsKeyGenerator();

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultUserValidatorFactory")})
    private UserValidatorFactory validatorFactory;

    @Autowired
    public DefaultUserPasswordService(UserRepository repository, PasswordEncoder encoder) {
        this.repository = repository;
        this.encoder = encoder;
    }

    @Override
    @Transactional
    public UserProfile changePassword(Principal principal, ChangePasswordRequest changeRequest) {
        User user = getUser(principal.getName());

        user.changePassword(changeRequest.getExistingPassword(), changeRequest.getNewPassword(), encoder);
        user.validation(validatorFactory);
        user.encrypted(encoder);

        return UserProfile.of(repository.save(user));
    }

    @Override
    @Transactional
    public UserProfile forgotPassword(String username) {
        User user = getUser(username);
        user.forgotPassword(keyGenerator);
        return UserProfile.of(repository.save(user));
    }

    @Override
    public boolean validateCredentialsKey(String username, String credentialsKey) {
        User user = getUser(username);

        return user.getPasswordCredentialsKey().matches(credentialsKey).equals(UserKeyMatchedResult.MATCHED);
    }

    @Override
    @Transactional
    public UserProfile resetPassword(ResetPasswordRequest resetRequest) {
        User user = getUser(resetRequest.getUsername());

        user.resetPassword(resetRequest.getCredentialsKey(), resetRequest.getNewPassword());
        user.validation(validatorFactory);
        user.encrypted(encoder);

        return UserProfile.of(repository.save(user));
    }

    private User getUser(String username) {
        return repository.findById(new Username(username))
                .orElseThrow(() -> UserNotFoundException.instance(username + " is not found"));
    }
}
