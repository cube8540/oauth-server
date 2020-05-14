package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.users.application.UserManagementService;
import cube8540.oauth.authentication.users.application.UserProfile;
import cube8540.oauth.authentication.users.application.UserRegisterRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("유저 관리 API 엔드 포인트 테스트")
class UserManagementAPIEndpointTest {

    private static final String EMAIL = "email@email.com";
    private static final String PASSWORD = "Password1234!@#$";

    private static final LocalDateTime REGISTERED_DATE_TIME = LocalDateTime.of(2020, 2, 24, 0, 34, 0);

    private UserManagementService service;
    private UserManagementAPIEndpoint endpoint;

    @BeforeEach
    void setup() {
        this.service = mock(UserManagementService.class);
        this.endpoint = new UserManagementAPIEndpoint(service);
    }

    @Nested
    @DisplayName("새 유저 추가 엔드 포인트 테스트")
    class RegisterNewUser {

        private UserRegisterRequest registerRequest;

        @BeforeEach
        void setup() {
            this.registerRequest = new UserRegisterRequest(EMAIL, PASSWORD);

            UserProfile userProfile = new UserProfile(EMAIL, REGISTERED_DATE_TIME);
            when(service.registerUser(registerRequest)).thenReturn(userProfile);
        }

        @Test
        @DisplayName("요청 받은 새 유저 정보를 등록해야 한다.")
        void shouldRegisterNewUserByInputData() {
            endpoint.registerUserAccounts(registerRequest);

            verify(service, times(1)).registerUser(registerRequest);
        }
    }

}