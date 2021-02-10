package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.users.application.UserCredentialsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("유저 인증 API 엔드포인트 테스트")
class UserCredentialsAPIEndpointTest {

    private static final String USERNAME = "username";
    private static final String CREDENTIALS_KEY = "CREDENTIALS-KEY";

    private UserCredentialsService service;
    private UserCredentialsAPIEndpoint endpoint;

    @BeforeEach
    void setup() {
        this.service = mock(UserCredentialsService.class);
        this.endpoint = new UserCredentialsAPIEndpoint(service);
    }

    @Test
    @DisplayName("계정 활성화")
    void userAccountActive() {
        endpoint.credentials(USERNAME,CREDENTIALS_KEY);

        verify(service, times(1)).accountCredentials(USERNAME, CREDENTIALS_KEY);
    }

    @Test
    @DisplayName("새 인증키 할당")
    void userGeneratedNewCredentialsKey() {
        endpoint.generateCredentialsKey(USERNAME);

        verify(service, times(1)).grantCredentialsKey(USERNAME);
    }
}