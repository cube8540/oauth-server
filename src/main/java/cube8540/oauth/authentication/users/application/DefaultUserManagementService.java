package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
import cube8540.oauth.authentication.users.error.UserNotFoundException;
import cube8540.oauth.authentication.users.error.UserRegisterException;
import cube8540.oauth.authentication.users.infra.DefaultUserValidationPolicy;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DefaultUserManagementService implements UserManagementService {

    private final UserRepository repository;
    private final PasswordEncoder encoder;

    @Setter
    private UserValidationPolicy validationPolicy = new DefaultUserValidationPolicy();

    @Autowired
    public DefaultUserManagementService(UserRepository repository, PasswordEncoder encoder) {
        this.repository = repository;
        this.encoder = encoder;
    }

    @Override
    public Long countUser(String email) {
        return repository.countByEmail(new UserEmail(email));
    }

    @Override
    public UserProfile loadUserProfile(String email) {
        return UserProfile.of(getUser(email));
    }

    @Override
    @Transactional
    public UserProfile registerUser(UserRegisterRequest registerRequest) {
        if (repository.countByEmail(new UserEmail(registerRequest.getEmail())) > 0) {
            throw UserRegisterException.existsIdentifier(registerRequest.getEmail() + " is exists");
        }
        User registerUser = new User(registerRequest.getEmail(), registerRequest.getPassword());
        registerUser.validation(validationPolicy);
        registerUser.encrypted(encoder);
        return UserProfile.of(repository.save(registerUser));
    }

    @Override
    @Transactional
    public UserProfile removeUser(String email) {
        User registerUser = getUser(email);

        repository.delete(registerUser);
        return UserProfile.of(registerUser);
    }

    private User getUser(String email) {
        return repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> UserNotFoundException.instance(email + " is not found"));
    }
}
