package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
import cube8540.oauth.authentication.users.domain.Username;
import cube8540.oauth.authentication.users.domain.exception.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.exception.UserRegisterException;
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
    public Long countUser(String username) {
        return repository.countByUsername(new Username(username));
    }

    @Override
    public UserProfile loadUserProfile(String username) {
        return UserProfile.of(getUser(username));
    }

    @Override
    @Transactional
    public UserProfile registerUser(UserRegisterRequest registerRequest) {
        if (repository.countByUsername(new Username(registerRequest.getUsername())) > 0) {
            throw UserRegisterException.existsIdentifier(registerRequest.getUsername() + " is exists");
        }
        User registerUser = new User(registerRequest.getUsername(), registerRequest.getEmail(), registerRequest.getPassword());
        registerUser.validation(validationPolicy);
        registerUser.encrypted(encoder);
        return UserProfile.of(repository.save(registerUser));
    }

    @Override
    @Transactional
    public UserProfile removeUser(String username) {
        User registerUser = getUser(username);

        repository.delete(registerUser);
        return UserProfile.of(registerUser);
    }

    private User getUser(String username) {
        return repository.findByUsername(new Username(username))
                .orElseThrow(() -> UserNotFoundException.instance(username + " is not found"));
    }
}
