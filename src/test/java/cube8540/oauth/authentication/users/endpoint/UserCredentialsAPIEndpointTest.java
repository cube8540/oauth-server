package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.users.application.UserCredentialsService;
import cube8540.oauth.authentication.users.application.UserProfile;
import cube8540.oauth.authentication.users.domain.exception.UserNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.support.SessionStatus;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("유저 인증 API 엔드포인트 테스트")
class UserCredentialsAPIEndpointTest {

    private static final String EMAIL = "email@email.com";

    private static final LocalDateTime REGISTERED_DATE_TIME = LocalDateTime.of(2020, 2, 24, 0, 34, 0);

    private static final String CREDENTIALS_KEY = "CREDENTIALS-KEY";

    private UserCredentialsService service;
    private UserCredentialsAPIEndpoint endpoint;

    @BeforeEach
    void setup() {
        this.service = mock(UserCredentialsService.class);
        this.endpoint = new UserCredentialsAPIEndpoint(service);
    }

    @Nested
    @DisplayName("계정 활성화")
    class UserActive {

        @Nested
        @DisplayName("세션에 새 유저 정보가 없을시")
        class WhenNotSavedNewRegisteredUserInSession {
            private Map<String, Object> model;
            private SessionStatus sessionStatus;

            @BeforeEach
            void setup() {
                this.model = new HashMap<>();
                this.sessionStatus = mock(SessionStatus.class);
                this.model.put(UserManagementAPIEndpoint.NEW_REGISTERED_USER_ATTRIBUTE, null);
            }

            @Test
            @DisplayName("UserNotFoundException이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> endpoint.credentials(CREDENTIALS_KEY, model, sessionStatus));
            }

            @Test
            @DisplayName("세션을 비워야 한다.")
            void shouldCleanupSession() {
                assertThrows(UserNotFoundException.class, () -> endpoint.credentials(CREDENTIALS_KEY, model, sessionStatus));
                verify(sessionStatus, times(1)).setComplete();
            }
        }

        @Nested
        @DisplayName("세션에 새 유저 정보가 있을시")
        class WhenSavedNewRegisteredUserInSession {
            private Map<String, Object> model;
            private SessionStatus sessionStatus;

            @BeforeEach
            void setup() {
                UserProfile newRegisteredUser = new UserProfile(EMAIL, REGISTERED_DATE_TIME);
                this.model = new HashMap<>();
                this.sessionStatus = mock(SessionStatus.class);
                this.model.put(UserManagementAPIEndpoint.NEW_REGISTERED_USER_ATTRIBUTE, newRegisteredUser);
            }

            @Test
            @DisplayName("새 유저를 요청 받은 인증키로 인증 받아야 한다.")
            void shouldCredentialsNewRegisteredUserForInputCredentialsKey() {
                endpoint.credentials(CREDENTIALS_KEY, model, sessionStatus);
                verify(service, times(1)).accountCredentials(EMAIL, CREDENTIALS_KEY);
            }

            @Test
            @DisplayName("세션을 비워야 한다.")
            void shouldCleanupSession() {
                endpoint.credentials(CREDENTIALS_KEY, model, sessionStatus);
                verify(sessionStatus, times(1)).setComplete();
            }
        }
    }

}