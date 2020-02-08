package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserKeyMatchedResult;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserPasswordEncoder;
import cube8540.oauth.authentication.users.domain.UserRepository;

public class DefaultUserPasswordService implements UserPasswordService {

    private final UserRepository repository;

    private final UserPasswordEncoder encoder;

    private final UserCredentialsKeyGenerator keyGenerator;

    public DefaultUserPasswordService(UserRepository repository, UserPasswordEncoder encoder, UserCredentialsKeyGenerator keyGenerator) {
        this.repository = repository;
        this.encoder = encoder;
        this.keyGenerator = keyGenerator;
    }

    @Override
    public UserProfile changePassword(ChangePasswordRequest changeRequest) {
        User user = repository.findByEmail(new UserEmail(changeRequest.getEmail()))
                .orElseThrow(() -> new UserNotFoundException(changeRequest.getEmail() + " user not found"));

        user.changePassword(changeRequest.getExistingPassword(), changeRequest.getNewPassword(), encoder);
        return new UserProfile(repository.save(user));
    }

    @Override
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
    public UserProfile resetPassword(ResetPasswordRequest resetRequest) {
        User user = repository.findByEmail(new UserEmail(resetRequest.getEmail()))
                .orElseThrow(() -> new UserNotFoundException(resetRequest.getEmail() + " user not found"));
        user.resetPassword(resetRequest.getCredentialsKey(), resetRequest.getNewPassword(), encoder);
        return new UserProfile(repository.save(user));
    }
}
