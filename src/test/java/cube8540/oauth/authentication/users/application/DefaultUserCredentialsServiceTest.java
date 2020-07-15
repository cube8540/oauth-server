package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.exception.UserNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_CREDENTIALS_KEY;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeDefaultUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeEmptyUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeKeyGenerator;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeUserRepository;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;

@DisplayName("기본 유저 인증 서비스 테스트")
class DefaultUserCredentialsServiceTest {

    @Test
    @DisplayName("저장소에 저장 되지 않은 유저에게 인증키 할당")
    void grantCredentialsKeyToNotRegisteredUserInRepository() {
        UserRepository repository = makeEmptyUserRepository();

        UserCredentialsService service = new DefaultUserCredentialsService(repository);

        assertThrows(UserNotFoundException.class, () -> service.grantCredentialsKey(RAW_USERNAME));
    }

    @Test
    @DisplayName("저장소에 저장된 유저에게 인증키 할당")
    void grantCredentialsKeyToRegisteredUserInRepository() {
        User user = makeDefaultUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        UserCredentialsKeyGenerator keyGenerator = makeKeyGenerator();

        DefaultUserCredentialsService service = new DefaultUserCredentialsService(repository);
        InOrder inOrder = inOrder(user, repository);
        service.setKeyGenerator(keyGenerator);
        service.grantCredentialsKey(RAW_USERNAME);

        inOrder.verify(user).generateCredentialsKey(keyGenerator);
        inOrder.verify(repository, times(1)).save(user);
    }

    @Test
    @DisplayName("저장 되지 않은 유저 계정 인증")
    void accountAuthenticationToNotRegisteredUserInRepository() {
        UserRepository repository = makeEmptyUserRepository();

        DefaultUserCredentialsService service = new DefaultUserCredentialsService(repository);

        assertThrows(UserNotFoundException.class, () -> service.accountCredentials(RAW_USERNAME, RAW_CREDENTIALS_KEY));
    }

    @Test
    @DisplayName("유저 계정 인증")
    void accountAuthenticationToUser() {
        User user = makeDefaultUser();
        UserRepository repository = makeUserRepository(USERNAME, user);

        DefaultUserCredentialsService service = new DefaultUserCredentialsService(repository);
        InOrder inOrder = inOrder(user, repository);

        service.accountCredentials(RAW_USERNAME, RAW_CREDENTIALS_KEY);
        inOrder.verify(user, times(1)).credentials(RAW_CREDENTIALS_KEY);
        inOrder.verify(repository, times(1)).save(user);
    }
}