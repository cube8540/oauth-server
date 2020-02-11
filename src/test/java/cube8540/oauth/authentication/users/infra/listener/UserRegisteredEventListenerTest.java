package cube8540.oauth.authentication.users.infra.listener;

import cube8540.oauth.authentication.users.application.UserCredentialsService;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserRegisterEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("유저 등록 이벤트 리스너 테스트")
class UserRegisteredEventListenerTest {

    public static final String RAW_EMAIL = "email@email.com";
    private UserCredentialsService credentialsService;
    private UserRegisteredEventListener eventListener;

    @BeforeEach
    void setup() {
        this.credentialsService = mock(UserCredentialsService.class);
        this.eventListener = new UserRegisteredEventListener(credentialsService);
    }

    @Nested
    @DisplayName("유저 등록 이벤트 리스닝")
    class ListeningUserRegisteredEvent {

        private UserRegisterEvent event;

        @BeforeEach
        void setup() {
            UserEmail email = new UserEmail(RAW_EMAIL);
            this.event = new UserRegisterEvent(email);
        }

        @Test
        @DisplayName("등록된 유저에게 인증키를 할당해야 한다.")
        void shouldGenerateCredentialsKeyForRegisterUser() {
            eventListener.handle(event);

            verify(credentialsService, times(1)).grantCredentialsKey(RAW_EMAIL);
        }
    }

}