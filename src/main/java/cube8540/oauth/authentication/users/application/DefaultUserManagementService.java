package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserAlreadyExistsException;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
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
        return repository.findByEmail(new UserEmail(email))
                .map(UserProfile::new).orElseThrow(() -> new UserNotFoundException(email + " user not found"));
    }

    @Override
    @Transactional
    public UserProfile registerUser(UserRegisterRequest registerRequest) {
        if (repository.countByEmail(new UserEmail(registerRequest.getEmail())) > 0) {
            throw new UserAlreadyExistsException(registerRequest.getEmail() + " is exists");
        }
        User registerUser = new User(registerRequest.getEmail(), registerRequest.getPassword());
        registerUser.validation(validationPolicy);
        registerUser.encrypted(encoder);
        return new UserProfile(repository.save(registerUser));
    }

    @Override
    @Transactional
    public UserProfile removeUser(String email) {
        User registerUser = repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> new UserNotFoundException(email + " user not found"));
        repository.delete(registerUser);
        return new UserProfile(registerUser);
    }
}
