package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
import cube8540.oauth.authentication.users.domain.exception.UserErrorCodes;
import cube8540.oauth.authentication.users.domain.exception.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.exception.UserRegisterException;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.EMAIL;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.ENCODED_PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeCountingUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeDefaultUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeEmptyUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makePasswordEncoder;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeUserRegisterRequest;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeValidationPolicy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 유저 계정 관리 서비스 테스트")
class DefaultUserManagementServiceTest {

    @Test
    @DisplayName("유저 카운팅")
    void userCounting() {
        long randomCount = (long) (Math.random() * 100);
        UserRepository repository = makeCountingUserRepository(USERNAME, randomCount);
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);
        DefaultUserManagementService service = new DefaultUserManagementService(repository, encoder);

        long result = service.countUser(RAW_USERNAME);
        assertEquals(randomCount, result);
    }

    @Test
    @DisplayName("저장소에 없는 유저 프로필 검색")
    void loadUserProfileToNotRegisteredInRepository() {
        UserRepository repository = makeEmptyUserRepository();
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserManagementService service = new DefaultUserManagementService(repository, encoder);

        assertThrows(UserNotFoundException.class, () -> service.loadUserProfile(RAW_USERNAME));
    }

    @Test
    @DisplayName("이미 저장소에 등록된 유저 영속화")
    void persistUserToAlreadyRegisteredInRepository() {
        User user = makeDefaultUser();
        UserRegisterRequest request = makeUserRegisterRequest();
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);
        UserRepository repository = makeUserRepository(USERNAME, user);

        DefaultUserManagementService service = new DefaultUserManagementService(repository, encoder);

        UserRegisterException e = assertThrows(UserRegisterException.class, () -> service.registerUser(request));
        assertEquals(UserErrorCodes.EXISTS_IDENTIFIER, e.getCode());
    }

    @Test
    @DisplayName("저장소에 유저 등록")
    void persistUserInRepository() {
        UserRepository repository = makeEmptyUserRepository();
        UserValidationPolicy policy = makeValidationPolicy();
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);
        UserRegisterRequest registerRequest = makeUserRegisterRequest();

        DefaultUserManagementService service = new DefaultUserManagementService(repository, encoder);
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        service.setValidationPolicy(policy);

        service.registerUser(registerRequest);
        verifySaveAfterValidation(policy.usernameRule(), userCaptor, repository);
        verifySaveAfterValidation(policy.passwordRule(), userCaptor, repository);
        verifySaveAfterValidation(policy.emailRule(), userCaptor, repository);
        assertEquals(USERNAME, userCaptor.getValue().getUsername());
        assertEquals(ENCODED_PASSWORD, userCaptor.getValue().getPassword());
        assertEquals(EMAIL, userCaptor.getValue().getEmail());
    }

    @Test
    @DisplayName("저장소에 저장 되지 않은 유저 삭제")
    void removeUserToNotRegisteredInRepository() {
        UserRepository repository = makeEmptyUserRepository();
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);

        DefaultUserManagementService service = new DefaultUserManagementService(repository, encoder);
        assertThrows(UserNotFoundException.class, () -> service.removeUser(RAW_USERNAME));
    }

    @Test
    @DisplayName("저장소에서 유저 삭제")
    void removeUser() {
        User user = makeDefaultUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

        DefaultUserManagementService service = new DefaultUserManagementService(repository, encoder);

        service.removeUser(RAW_USERNAME);
        verify(repository, times(1)).delete(userCaptor.capture());
        assertEquals(user, userCaptor.getValue());
    }

    private void verifySaveAfterValidation(ValidationRule<User> rule, ArgumentCaptor<User> argumentCaptor, UserRepository repository) {
        InOrder inOrder = inOrder(rule, repository);
        inOrder.verify(rule, times(1)).isValid(argumentCaptor.capture());
        inOrder.verify(repository, times(1)).save(argumentCaptor.capture());
        assertEquals(argumentCaptor.getAllValues().get(0), argumentCaptor.getAllValues().get(1));
    }
}