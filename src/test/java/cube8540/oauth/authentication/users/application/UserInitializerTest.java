package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.password.PasswordEncoder;

import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.ENCODED_PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeDefaultUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeEmptyUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makePasswordEncoder;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeUserRepository;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("유저 초기화 테스트")
public class UserInitializerTest {

    private static final String INIT_USERNAME_KEY = "init-user.username";
    private static final String INIT_PASSWORD_KEY = "init-user.password";

    @Test
    @DisplayName("초기화 유저가 저장소에 없을시")
    void initializeWhenUserIsNotExists() {
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        UserRepository repository = makeEmptyUserRepository();
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);
        Environment environment = mock(Environment.class);
        UserInitializer initializer = new UserInitializer(repository, encoder);

        when(environment.getRequiredProperty(INIT_USERNAME_KEY)).thenReturn(RAW_USERNAME);
        when(environment.getRequiredProperty(INIT_PASSWORD_KEY)).thenReturn(PASSWORD);

        initializer.initialize(environment);
        verify(repository, times(1)).save(userCaptor.capture());
        assertEquals(USERNAME, userCaptor.getValue().getUsername());
        assertEquals(ENCODED_PASSWORD, userCaptor.getValue().getPassword());
        assertTrue(userCaptor.getValue().getCredentialed());
    }

    @Test
    @DisplayName("초기화 유저가 이미 저장소에 있을시")
    void initializeWhenUserIsExists() {
        User user = makeDefaultUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCODED_PASSWORD);
        Environment environment = mock(Environment.class);
        UserInitializer initializer = new UserInitializer(repository, encoder);

        when(environment.getRequiredProperty(INIT_USERNAME_KEY)).thenReturn(RAW_USERNAME);
        when(environment.getRequiredProperty(INIT_PASSWORD_KEY)).thenReturn(PASSWORD);

        initializer.initialize(environment);
        verify(repository, never()).save(any());
    }
}
