package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.users.domain.ApprovalAuthority;
import cube8540.oauth.authentication.users.domain.Uid;
import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKey;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserKeyMatchedResult;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidatorFactory;
import cube8540.oauth.authentication.users.domain.Username;
import cube8540.validator.core.ValidationResult;
import cube8540.validator.core.Validator;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserApplicationTestHelper {

    static final String RAW_USERNAME = "username";
    static final Username USERNAME = new Username(RAW_USERNAME);

    static final String RAW_UID = "UID";
    static final Uid UID = new Uid(RAW_UID);

    static final String PASSWORD = "Password1234!@#$";
    static final String NEW_PASSWORD = "NewPassword1234!@#$";
    static final String ENCODED_PASSWORD =  "$2a$10$MrsAcjEPfD4ktbWEb13SBu.lE2OfGWZ2NPqgUoSTeWA7bvh9.k3WC";

    static final String RAW_CREDENTIALS_KEY = "CREDENTIALS-KEY";
    static final String RAW_PASSWORD_CREDENTIALS_KEY = "PASSWORD-CREDENTIALS-KEY";
    static final UserCredentialsKey PASSWORD_CREDENTIALS_KEY = new UserCredentialsKey(RAW_PASSWORD_CREDENTIALS_KEY);

    static final String CLIENT_A_ID = "CLIENT-A";
    static final String CLIENT_B_ID = "CLIENT-B";
    static final String CLIENT_C_ID = "CLIENT-C";

    static final Set<String> CLIENT_A_APPROVAL_AUTHORITIES = new HashSet<>(Arrays.asList("TEST-1", "TEST-2", "TEST-3"));
    static final Set<String> CLIENT_B_APPROVAL_AUTHORITIES = new HashSet<>(Arrays.asList("TEST-2", "TEST-3", "TEST-4"));
    static final Set<String> CLIENT_C_APPROVAL_AUTHORITIES = new HashSet<>(Arrays.asList("TEST-3", "TEST-4", "TEST-5"));

    public static final Set<ApprovalAuthority> AUTHORITIES_A = CLIENT_A_APPROVAL_AUTHORITIES.stream()
            .map(scope -> new ApprovalAuthority(CLIENT_A_ID, scope)).collect(Collectors.toSet());
    public static final Set<ApprovalAuthority> AUTHORITIES_B = CLIENT_B_APPROVAL_AUTHORITIES.stream()
            .map(scope -> new ApprovalAuthority(CLIENT_B_ID, scope)).collect(Collectors.toSet());
    public static final Set<ApprovalAuthority> AUTHORITIES_C = CLIENT_C_APPROVAL_AUTHORITIES.stream()
            .map(scope -> new ApprovalAuthority(CLIENT_C_ID, scope)).collect(Collectors.toSet());

    static final Set<String> REQUEST_SCOPES = new HashSet<>(Arrays.asList("TEST-1", "TEST-2", "TEST-3", "TEST-4", "TEST-5"));
    static final Set<String> ALL_APPROVAL_SCOPES = new HashSet<>(Arrays.asList("TEST-1", "TEST-2", "TEST-3"));

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
        when(user.getUid()).thenReturn(UID);
        when(user.getPassword()).thenReturn(PASSWORD);

        return user;
    }

    static UserCredentialsKeyGenerator makeKeyGenerator() {
        return mock(UserCredentialsKeyGenerator.class);
    }

    static UserCredentialsKeyGenerator makeKeyGenerator(String key) {
        UserCredentialsKeyGenerator generator = makeKeyGenerator();

        when(generator.generateKey()).thenReturn(new UserCredentialsKey(key));

        return generator;
    }

    static PasswordEncoder makePasswordEncoder(String rawPassword, String encodedPassword) {
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        when(encoder.encode(rawPassword)).thenReturn(encodedPassword);
        when(encoder.matches(rawPassword, encodedPassword)).thenReturn(true);

        return encoder;
    }

    static UserRegisterRequest makeUserRegisterRequest() {
        return new UserRegisterRequest(RAW_USERNAME, PASSWORD);
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

        when(user.getCredentialed()).thenReturn(false);

        return user;
    }

    static User makeCertifiedUser() {
        User user = makeDefaultUser();

        when(user.getCredentialed()).thenReturn(true);

        return user;
    }

    static User makeNotGeneratedPasswordCredentialsKeyUser() {
        User user = makeDefaultUser();

        when(user.getPasswordCredentialsKey()).thenReturn(null);

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

    static Set<ApprovalAuthority> makeComposeApprovalAuthorities() {
        Set<ApprovalAuthority> compose = new HashSet<>();
        compose.addAll(AUTHORITIES_A);
        compose.addAll(AUTHORITIES_B);
        compose.addAll(AUTHORITIES_C);

        return compose;
    }

    static Principal makeAuthentication(String username) {
        Principal authentication = mock(Authentication.class);

        when(authentication.getName()).thenReturn(username);

        return authentication;
    }

    static OAuth2ClientDetails makeClientDetails(String clientId) {
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);

        when(clientDetails.getClientId()).thenReturn(clientId);

        return clientDetails;
    }
}
