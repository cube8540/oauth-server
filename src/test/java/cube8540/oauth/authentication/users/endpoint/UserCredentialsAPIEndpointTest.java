package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.message.ResponseMessage;
import cube8540.oauth.authentication.message.SuccessResponseMessage;
import cube8540.oauth.authentication.users.application.UserCredentialsService;
import cube8540.oauth.authentication.users.application.UserProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("계저 인증 엔드 포인트 테스트")
class UserCredentialsAPIEndpointTest {

    private static final String EMAIL = "email@email.com";

    private static final String CREDENTIALS_KEY = "CREDENTIALS-KEY";

    private static final LocalDateTime REGISTERED_AT = LocalDateTime.of(2020, 2, 11, 20, 58);

    private UserCredentialsService service;
    private UserCredentialsAPIEndpoint endpoint;

    @BeforeEach
    void setup() {
        this.service = mock(UserCredentialsService.class);
        this.endpoint = new UserCredentialsAPIEndpoint(service);
    }

    @Nested
    @DisplayName("계정 인증")
    class AccountCredentials {

        private UserProfile userProfile;

        @BeforeEach
        void setup() {
            this.userProfile = new UserProfile(EMAIL, REGISTERED_AT);

            when(service.accountCredentials(EMAIL, CREDENTIALS_KEY)).thenReturn(userProfile);
        }

        @Test
        @DisplayName("요청 받은 이메일의 인증을 해야 한다.")
        void shouldCredentialsRequestingEmail() {
            endpoint.credentials(EMAIL, CREDENTIALS_KEY);

            verify(service, times(1)).accountCredentials(eq(EMAIL), any());
        }

        @Test
        @DisplayName("요청 받은 인증키로 인증을 해야 한다.")
        void shouldCredentialsViaRequestingCredentialsKey() {
            endpoint.credentials(EMAIL, CREDENTIALS_KEY);

            verify(service, times(1)).accountCredentials(any(), eq(CREDENTIALS_KEY));
        }

        @Test
        @DisplayName("상태 코드는 200 이어야 한다.")
        void shouldHttpStatusCodeIs200() {
            ResponseEntity<ResponseMessage> response = endpoint.credentials(EMAIL, CREDENTIALS_KEY);
            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("인증을 받은 계정의 정보를 반환해야 한다.")
        void shouldReturnsCredentialsUserProfile() {
            ResponseEntity<ResponseMessage> response = endpoint.credentials(EMAIL, CREDENTIALS_KEY);
            assertNotNull(response.getBody());
            assertEquals(userProfile, ((SuccessResponseMessage<?>) response.getBody()).getData());
        }
    }

}