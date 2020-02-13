package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserKeyMatchedResult;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
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
        User user = repository.findByEmail(new UserEmail(principal.getName()))
                .orElseThrow(() -> new UserNotFoundException(principal.getName() + " user not found"));

        user.changePassword(encoder.encode(changeRequest.getExistingPassword()), changeRequest.getNewPassword());
        user.validation(validationPolicy);
        user.encrypted(encoder);

        return new UserProfile(repository.save(user));
    }

    @Override
    @Transactional
    public UserProfile forgotPassword(String email) {
        User user = repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> new UserNotFoundException(email + " user not found"));
        user.forgotPassword(keyGenerator);
        return new UserProfile(repository.save(user));
    }

    @Override
    public boolean validateCredentialsKey(String email, String credentialsKey) {
        User user = repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> new UserNotFoundException(email + " user not found"));

        return user.getPasswordCredentialsKey().matches(credentialsKey).equals(UserKeyMatchedResult.MATCHED);
    }

    @Override
    @Transactional
    public UserProfile resetPassword(ResetPasswordRequest resetRequest) {
        User user = repository.findByEmail(new UserEmail(resetRequest.getEmail()))
                .orElseThrow(() -> new UserNotFoundException(resetRequest.getEmail() + " user not found"));

        user.resetPassword(resetRequest.getCredentialsKey(), resetRequest.getNewPassword());
        user.validation(validationPolicy);
        user.encrypted(encoder);

        return new UserProfile(repository.save(user));
    }
}
