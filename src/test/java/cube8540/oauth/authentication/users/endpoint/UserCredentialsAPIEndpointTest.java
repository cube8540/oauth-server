package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.users.application.UserCredentialsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("유저 인증 API 엔드포인트 테스트")
class UserCredentialsAPIEndpointTest {

    private static final String EMAIL = "email@email.com";

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

        @Test
        @DisplayName("요청 받은 유저를 요청 받은 인증키로 인증 받아야 한다.")
        void shouldCredentialsRequestUserByInputCredentialsKey() {
            endpoint.credentials(EMAIL, CREDENTIALS_KEY);
            verify(service, times(1)).accountCredentials(EMAIL, CREDENTIALS_KEY);
        }
    }

}