package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.users.application.UserManagementService;
import cube8540.oauth.authentication.users.application.UserProfile;
import cube8540.oauth.authentication.users.application.UserRegisterRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("유저 관리 API 엔드 포인트 테스트")
class UserManagementAPIEndpointTest {

    private static final String USERNAME = "username";
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

    @Test
    @DisplayName("새 유저 추가")
    void registerNewUser() {
        UserRegisterRequest request = new UserRegisterRequest(USERNAME, EMAIL, PASSWORD);
        UserProfile userProfile = new UserProfile(USERNAME, EMAIL, REGISTERED_DATE_TIME);

        when(service.registerUser(request)).thenReturn(userProfile);

        endpoint.registerUserAccounts(request);
        verify(service, times(1)).registerUser(request);
    }
}