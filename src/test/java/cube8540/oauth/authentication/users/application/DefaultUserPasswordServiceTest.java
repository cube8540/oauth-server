package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidatorFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.ENCODED_PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.NEW_PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.PASSWORD_CREDENTIALS_KEY;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_PASSWORD_CREDENTIALS_KEY;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeChangePasswordRequest;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeDefaultUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeEmptyUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeExpiredPasswordCredentialsKeyUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeKeyGenerator;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeMatchedPasswordCredentialsKeyUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeNotMatchedPasswordCredentialsKeyUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makePasswordEncoder;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeResetPasswordRequest;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeValidatorFactory;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 패스워드 서비스 테스트")
class DefaultUserPasswordServiceTest {

    @Test
    @DisplayName("저장소에 저장되지 않은 유저의 페스워드 수정")
    void changePasswordToNotRegisteredUserInRepository() {
        ChangePasswordRequest request = makeChangePasswordRequest();
        UserRepository repository = makeEmptyUserRepository();
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);

        assertThrows(UserNotFoundException.class, () -> service.changePassword(RAW_USERNAME, request));
    }

    @Test
    @DisplayName("패스워드 수정")
    void changePassword() {
        User user = makeDefaultUser();
        ChangePasswordRequest request = makeChangePasswordRequest();
        UserRepository repository = makeUserRepository(USERNAME, user);
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);
        UserValidatorFactory factory = makeValidatorFactory();

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);
        InOrder inOrder = inOrder(user, repository);
        service.setValidatorFactory(factory);

        service.changePassword(RAW_USERNAME, request);
        inOrder.verify(user, times(1)).changePassword(PASSWORD, NEW_PASSWORD, encoder);
        inOrder.verify(user, times(1)).validation(factory);
        inOrder.verify(user, times(1)).encrypted(encoder);
        inOrder.verify(repository, times(1)).save(user);
    }

    @Test
    @DisplayName("저장소에 저장되지 않은 유저의 패스워드 분실 요청")
    void forgotPasswordRequestToNotRegisteredUserInRepository() {
        UserRepository repository = makeEmptyUserRepository();
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);

        assertThrows(UserNotFoundException.class, () -> service.forgotPassword(RAW_USERNAME));
    }

    @Test
    @DisplayName("패스워드 분실 요청")
    void forgotPasswordRequest() {
        User user = makeDefaultUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        UserCredentialsKeyGenerator keyGenerator = makeKeyGenerator(RAW_PASSWORD_CREDENTIALS_KEY);
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);
        InOrder inOrder = inOrder(user, repository);
        service.setKeyGenerator(keyGenerator);
        when(user.getPasswordCredentialsKey()).thenReturn(PASSWORD_CREDENTIALS_KEY);

        ForgotUserPassword forgotUser = service.forgotPassword(RAW_USERNAME);
        inOrder.verify(user, times(1)).forgotPassword(keyGenerator);
        inOrder.verify(repository, times(1)).save(user);
        assertEquals(RAW_PASSWORD_CREDENTIALS_KEY, forgotUser.getCredentialsKey());
    }

    @Test
    @DisplayName("저장소에 저장되지 않은 유저의 인증키 검사")
    void validateCredentialsKeyToNotRegisteredUserInRepository() {
        UserRepository repository = makeEmptyUserRepository();
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);

        assertThrows(UserNotFoundException.class, () -> service.forgotPassword(RAW_USERNAME));
    }

    @Test
    @DisplayName("만료된 인증키 검사")
    void validateToExpiredCredentialsKey() {
        User user = makeExpiredPasswordCredentialsKeyUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);

        boolean validate = service.validateCredentialsKey(RAW_USERNAME, RAW_PASSWORD_CREDENTIALS_KEY);
        assertFalse(validate);
    }

    @Test
    @DisplayName("할당 되지 않은 인증키 검사")
    void validateToNotGeneratedKey() {
        User user = makeExpiredPasswordCredentialsKeyUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);

        boolean validate = service.validateCredentialsKey(RAW_USERNAME, RAW_PASSWORD_CREDENTIALS_KEY);
        assertFalse(validate);
    }

    @Test
    @DisplayName("서로 매칭 되지 않는 인증키 검사")
    void validateToNotMatchedCredentialsKey() {
        User user = makeNotMatchedPasswordCredentialsKeyUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);

        boolean validate = service.validateCredentialsKey(RAW_USERNAME, RAW_PASSWORD_CREDENTIALS_KEY);
        assertFalse(validate);
    }

    @Test
    @DisplayName("매칭 되는 인증키 검사")
    void validateToMatchedCredentialsKey() {
        User user = makeMatchedPasswordCredentialsKeyUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);

        boolean validate = service.validateCredentialsKey(RAW_USERNAME, RAW_PASSWORD_CREDENTIALS_KEY);
        assertTrue(validate);
    }

    @Test
    @DisplayName("저장소에 저장 되지 않은 유저의 패스워드 초기화")
    void resetPasswordToNotRegisteredUserInRepository() {
        ResetPasswordRequest request = makeResetPasswordRequest();
        UserRepository repository = makeEmptyUserRepository();
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);

        assertThrows(UserNotFoundException.class, () -> service.resetPassword(request));
    }

    @Test
    @DisplayName("패스워드 초기화")
    void resetPassword() {
        ResetPasswordRequest request = makeResetPasswordRequest();
        User user = makeDefaultUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        UserValidatorFactory factory = makeValidatorFactory();
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserPasswordService service = new DefaultUserPasswordService(repository, encoder);
        service.setValidatorFactory(factory);

        service.resetPassword(request);
        InOrder inOrder = inOrder(user, repository);
        inOrder.verify(user, times(1)).resetPassword(RAW_PASSWORD_CREDENTIALS_KEY, NEW_PASSWORD);
        inOrder.verify(user, times(1)).validation(factory);
        inOrder.verify(user, times(1)).encrypted(encoder);
        inOrder.verify(repository, times(1)).save(user);
    }
}