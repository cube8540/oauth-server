package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserKeyMatchedResult;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
import cube8540.oauth.authentication.users.error.UserNotFoundException;
import cube8540.oauth.authentication.users.infra.DefaultUserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.infra.DefaultUserValidationPolicy;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Setter
    private UserValidationPolicy validationPolicy = new DefaultUserValidationPolicy();

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
        user.validation(validationPolicy);
        user.encrypted(encoder);

        return UserProfile.of(repository.save(user));
    }

    @Override
    @Transactional
    public UserProfile forgotPassword(String email) {
        User user = getUser(email);
        user.forgotPassword(keyGenerator);
        return UserProfile.of(repository.save(user));
    }

    @Override
    public boolean validateCredentialsKey(String email, String credentialsKey) {
        User user = getUser(email);

        return user.getPasswordCredentialsKey().matches(credentialsKey).equals(UserKeyMatchedResult.MATCHED);
    }

    @Override
    @Transactional
    public UserProfile resetPassword(ResetPasswordRequest resetRequest) {
        User user = getUser(resetRequest.getEmail());

        user.resetPassword(resetRequest.getCredentialsKey(), resetRequest.getNewPassword());
        user.validation(validationPolicy);
        user.encrypted(encoder);

        return UserProfile.of(repository.save(user));
    }

    private User getUser(String email) {
        return repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> UserNotFoundException.instance(email + " is not found"));
    }
}
