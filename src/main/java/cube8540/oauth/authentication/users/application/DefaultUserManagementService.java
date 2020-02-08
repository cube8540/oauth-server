package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserAlreadyExistsException;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserPasswordEncoder;
import cube8540.oauth.authentication.users.domain.UserRepository;

public class DefaultUserManagementService implements UserManagementService {

    private final UserRepository repository;
    private final UserPasswordEncoder encoder;

    public DefaultUserManagementService(UserRepository repository, UserPasswordEncoder encoder) {
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
    public UserProfile registerUser(UserRegisterRequest registerRequest) {
        if (repository.countByEmail(new UserEmail(registerRequest.getEmail())) > 0) {
            throw new UserAlreadyExistsException(registerRequest.getEmail() + " is exists");
        }
        User registerUser = repository.save(new User(registerRequest.getEmail(), registerRequest.getPassword(), encoder));
        return new UserProfile(registerUser);
    }

    @Override
    public UserProfile removeUser(String email) {
        User registerUser = repository.findByEmail(new UserEmail(email))
                .orElseThrow(() -> new UserNotFoundException(email + " user not found"));
        repository.delete(registerUser);
        return new UserProfile(registerUser);
    }
}
