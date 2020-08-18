package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKey;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserKeyMatchedResult;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidatorFactory;
import cube8540.oauth.authentication.users.domain.Username;
import cube8540.validator.core.ValidationResult;
import cube8540.validator.core.Validator;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.Principal;
import java.util.Optional;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserApplicationTestHelper {

    static final String RAW_USERNAME = "username";
    static final Username USERNAME = new Username(RAW_USERNAME);

    static final String RAW_EMAIL = "email@email.com";
    static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    static final String PASSWORD = "Password1234!@#$";
    static final String NEW_PASSWORD = "NewPassword1234!@#$";
    static final String ENCODED_PASSWORD =  "$2a$10$MrsAcjEPfD4ktbWEb13SBu.lE2OfGWZ2NPqgUoSTeWA7bvh9.k3WC";

    static final String RAW_CREDENTIALS_KEY = "CREDENTIALS-KEY";
    static final String RAW_PASSWORD_CREDENTIALS_KEY = "PASSWORD-CREDENTIALS-KEY";

    static UserRepository makeUserRepository(Username username, User user) {
        UserRepository repository = mock(UserRepository.class);

        when(repository.findById(username)).thenReturn(Optional.ofNullable(user));
        when(repository.countByUsername(username)).thenReturn(1L);
        doAnswer(returnsFirstArg()).when(repository).save(isA(User.class));

        return repository;
    }

    static UserRepository makeCountingUserRepository(Username username, long count) {
        UserRepository repository = mock(UserRepository.class);

        when(repository.countByUsername(username)).thenReturn(count);

        return repository;
    }

    static UserRepository makeEmptyUserRepository() {
        UserRepository repository = mock(UserRepository.class);

        doAnswer(returnsFirstArg()).when(repository).save(isA(User.class));

        return repository;
    }

    static User makeDefaultUser() {
        User user = mock(User.class);

        when(user.getUsername()).thenReturn(USERNAME);
        when(user.getEmail()).thenReturn(EMAIL);
        when(user.getPassword()).thenReturn(PASSWORD);

        return user;
    }

    static UserCredentialsKeyGenerator makeKeyGenerator() {
        return mock(UserCredentialsKeyGenerator.class);
    }

    static PasswordEncoder makePasswordEncoder(String rawPassword, String encodedPassword) {
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        when(encoder.encode(rawPassword)).thenReturn(encodedPassword);
        when(encoder.matches(rawPassword, encodedPassword)).thenReturn(true);

        return encoder;
    }

    static UserRegisterRequest makeUserRegisterRequest() {
        return new UserRegisterRequest(RAW_USERNAME, RAW_EMAIL, PASSWORD);
    }

    static ChangePasswordRequest makeChangePasswordRequest() {
        return new ChangePasswordRequest(PASSWORD, NEW_PASSWORD);
    }

    static ResetPasswordRequest makeResetPasswordRequest() {
        return new ResetPasswordRequest(RAW_USERNAME, RAW_PASSWORD_CREDENTIALS_KEY, NEW_PASSWORD);
    }

    @SuppressWarnings("unchecked")
    static UserValidatorFactory makeValidatorFactory() {
        UserValidatorFactory factory = mock(UserValidatorFactory.class);
        ValidationResult result = mock(ValidationResult.class);
        Validator<User> validator = mock(Validator.class);

        when(validator.getResult()).thenReturn(result);
        when(factory.createValidator(any())).thenReturn(validator);

        return factory;
    }

    @SuppressWarnings("unchecked")
    static UserValidatorFactory makeErrorValidatorFactory(Exception exception) {
        UserValidatorFactory factory = mock(UserValidatorFactory.class);
        ValidationResult result = mock(ValidationResult.class);
        Validator<User> validator = mock(Validator.class);

        when(validator.getResult()).thenReturn(result);
        doAnswer(invocation -> {throw exception;}).when(result).hasErrorThrows(any());
        when(factory.createValidator(any())).thenReturn(validator);

        return factory;
    }

    static User makeNotCertifiedUser() {
        User user = makeDefaultUser();

        when(user.isCredentials()).thenReturn(false);

        return user;
    }

    static User makeCertifiedUser() {
        User user = makeDefaultUser();

        when(user.isCredentials()).thenReturn(true);

        return user;
    }

    static User makeExpiredPasswordCredentialsKeyUser() {
        User user = makeDefaultUser();
        UserCredentialsKey key = mock(UserCredentialsKey.class);

        when(key.matches(RAW_PASSWORD_CREDENTIALS_KEY)).thenReturn(UserKeyMatchedResult.EXPIRED);
        when(user.getPasswordCredentialsKey()).thenReturn(key);

        return user;
    }

    static User makeNotMatchedPasswordCredentialsKeyUser() {
        User user = makeDefaultUser();
        UserCredentialsKey key = mock(UserCredentialsKey.class);

        when(key.matches(RAW_PASSWORD_CREDENTIALS_KEY)).thenReturn(UserKeyMatchedResult.NOT_MATCHED);
        when(user.getPasswordCredentialsKey()).thenReturn(key);

        return user;
    }

    static User makeMatchedPasswordCredentialsKeyUser() {
        User user = makeDefaultUser();
        UserCredentialsKey key = mock(UserCredentialsKey.class);

        when(key.matches(RAW_PASSWORD_CREDENTIALS_KEY)).thenReturn(UserKeyMatchedResult.MATCHED);
        when(user.getPasswordCredentialsKey()).thenReturn(key);

        return user;
    }

    static Principal makePrincipal(String username) {
        Principal principal = mock(Principal.class);

        when(principal.getName()).thenReturn(username);
        return principal;
    }
}
