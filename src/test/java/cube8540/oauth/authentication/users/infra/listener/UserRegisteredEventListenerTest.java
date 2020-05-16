package cube8540.oauth.authentication.users.infra.listener;

import cube8540.oauth.authentication.users.application.UserCredentialsService;
import cube8540.oauth.authentication.users.domain.UserRegisterEvent;
import cube8540.oauth.authentication.users.domain.Username;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("유저 등록 이벤트 리스너 테스트")
class UserRegisteredEventListenerTest {

    private static final String RAW_USERNAME = "username1234";
    private static final Username USERNAME = new Username(RAW_USERNAME);

    private UserCredentialsService credentialsService;
    private UserRegisteredEventListener eventListener;

    @BeforeEach
    void setup() {
        this.credentialsService = mock(UserCredentialsService.class);
        this.eventListener = new UserRegisteredEventListener(credentialsService);
    }

    @Test
    @DisplayName("새 유저 등록 이벤트 발생시 등록된 계정에 인증키를 할당해야 한다.")
    void issuedRegisteredNewUserEventAnCredentialsKeyShouldBeAssignedToTheRegisteredAccount() {
        UserRegisterEvent event = new UserRegisterEvent(USERNAME);

        eventListener.handle(event);

        verify(credentialsService, times(1)).grantCredentialsKey(RAW_USERNAME);
    }

}