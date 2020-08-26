package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidatorFactory;
import cube8540.oauth.authentication.users.domain.Username;
import cube8540.oauth.authentication.users.domain.exception.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.exception.UserRegisterException;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DefaultUserManagementService implements UserManagementService {

    private final UserRepository repository;
    private final PasswordEncoder encoder;

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultUserValidatorFactory")})
    private UserValidatorFactory validatorFactory;

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
        registerUser.validation(validatorFactory);
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
        return repository.findById(new Username(username))
                .orElseThrow(() -> UserNotFoundException.instance(username + " is not found"));
    }
}
