package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.message.ResponseMessage;
import cube8540.oauth.authentication.message.SuccessResponseMessage;
import cube8540.oauth.authentication.users.application.ChangePasswordRequest;
import cube8540.oauth.authentication.users.application.ResetPasswordRequest;
import cube8540.oauth.authentication.users.application.UserPasswordService;
import cube8540.oauth.authentication.users.application.UserProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("패스워드 API 엔드 포인트 테스트")
class UserPasswordAPIEndpointTest {

    private static final String EMAIL = "email@email.com";
    private static final String CREDENTIALS_KEY = "CREDENTIALS-KEY";
    private static final String EXISTS_PASSWORD = "EXISTS-PASSWORD";
    private static final String NEW_PASSWORD = "NEW-PASSWORD";

    private UserPasswordService service;
    private UserPasswordAPIEndpoint endpoint;

    @BeforeEach
    void setup() {
        this.service = mock(UserPasswordService.class);
        this.endpoint = new UserPasswordAPIEndpoint(service);
    }

    @Nested
    @DisplayName("패스워드 분실")
    class ForgotPassword {
        private UserProfile userProfile;

        @BeforeEach
        void setup() {
            this.userProfile = new UserProfile(EMAIL, LocalDateTime.now());

            when(service.forgotPassword(EMAIL)).thenReturn(userProfile);
        }

        @Test
        @DisplayName("요청 받은 이메일의 패스워드 분실을 요청해야 한다.")
        void shouldCallForgotPasswordForRequestingEmail() {
            endpoint.forgotPassword(EMAIL);

            verify(service, times(1)).forgotPassword(EMAIL);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 200 이어야 한다.")
        void shouldHttpStatusCodeIs200() {
            ResponseEntity<ResponseMessage> response = endpoint.forgotPassword(EMAIL);

            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("응답 바디에는 패스워드를 분실한 계정의 정보를 반환해야 한다.")
        void shouldResponseBodyContainsForgotPasswordAccounts() {
            ResponseEntity<ResponseMessage> response = endpoint.forgotPassword(EMAIL);

            assertNotNull(response.getBody());
            assertEquals(userProfile, ((SuccessResponseMessage<?>) response.getBody()).getData());
        }
    }

    @Nested
    @DisplayName("패스워드 수정")
    class ChangePassword {
        private Principal principal;
        private Map<String, String> parameterMap;
        private UserProfile userProfile;

        @BeforeEach
        void setup() {
            this.principal = mock(Principal.class);
            this.parameterMap = new HashMap<>();
            this.userProfile = new UserProfile(EMAIL, LocalDateTime.now());

            parameterMap.put("existsPassword", EXISTS_PASSWORD);
            parameterMap.put("newPassword", NEW_PASSWORD);

            when(principal.getName()).thenReturn(EMAIL);
            when(service.changePassword(any())).thenReturn(userProfile);
        }

        @Test
        @DisplayName("인증 받은 사용자의 패스워드를 수정해야 한다.")
        void shouldChangePasswordForAuthenticationUser() {
            ArgumentCaptor<ChangePasswordRequest> requestCaptor = ArgumentCaptor.forClass(ChangePasswordRequest.class);

            endpoint.changePassword(principal, parameterMap);
            verify(service, times(1)).changePassword(requestCaptor.capture());
            assertEquals(EMAIL, requestCaptor.getValue().getEmail());
        }

        @Test
        @DisplayName("요청 받은 이전에 사용하던 패스워드로 패스워드를 변경해야 한다.")
        void shouldChangePasswordViaExistsPassword() {
            ArgumentCaptor<ChangePasswordRequest> requestCaptor = ArgumentCaptor.forClass(ChangePasswordRequest.class);

            endpoint.changePassword(principal, parameterMap);
            verify(service, times(1)).changePassword(requestCaptor.capture());
            assertEquals(EXISTS_PASSWORD, requestCaptor.getValue().getExistingPassword());
        }

        @Test
        @DisplayName("요청 받은 새 패스워드로 패스워드를 변경해야 한다.")
        void shouldChangePasswordViaNewPassword() {
            ArgumentCaptor<ChangePasswordRequest> requestCaptor = ArgumentCaptor.forClass(ChangePasswordRequest.class);

            endpoint.changePassword(principal, parameterMap);
            verify(service, times(1)).changePassword(requestCaptor.capture());
            assertEquals(NEW_PASSWORD, requestCaptor.getValue().getNewPassword());
        }

        @Test
        @DisplayName("HTTP 상태 코드는 200 이어야 한다.")
        void shouldHttpStatusCodeIs200() {
            ResponseEntity<ResponseMessage> response = endpoint.changePassword(principal, parameterMap);

            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("응답 바디에는 패스워드를 변경한 계정의 정보를 반환해야 한다.")
        void shouldResponseBodyContainsChangedPasswordAccounts() {
            ResponseEntity<ResponseMessage> response = endpoint.changePassword(principal, parameterMap);

            assertNotNull(response.getBody());
            assertEquals(userProfile, ((SuccessResponseMessage<?>) response.getBody()).getData());
        }
    }

    @Nested
    @DisplayName("패스워드 초기화")
    class ResetPassword {
        private UserProfile userProfile;

        private ResetPasswordRequest resetPasswordRequest;

        @BeforeEach
        void setup() {
            this.userProfile = new UserProfile(EMAIL, LocalDateTime.now());
            this.resetPasswordRequest = new ResetPasswordRequest(EMAIL, CREDENTIALS_KEY, NEW_PASSWORD);

            when(service.resetPassword(resetPasswordRequest)).thenReturn(userProfile);
        }

        @Test
        @DisplayName("요청 받은 정보로 패스워드를 초기화 해야 한다.")
        void shouldResetPasswordViaRequestingInformation() {
            ArgumentCaptor<ResetPasswordRequest> requestCaptor = ArgumentCaptor.forClass(ResetPasswordRequest.class);

            endpoint.resetPassword(resetPasswordRequest);
            verify(service, times(1)).resetPassword(requestCaptor.capture());
            assertEquals(resetPasswordRequest, requestCaptor.getValue());
        }

        @Test
        @DisplayName("HTTP 상태 코드는 200 이어야 한다.")
        void shouldHttpStatusCodeIs200() {
            ResponseEntity<ResponseMessage> response = endpoint.resetPassword(resetPasswordRequest);

            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("응답 바디에는 패스워드를 초기화한 계정의 정보를 반환해야 한다.")
        void shouldResponseBodyContainsResetPasswordAccounts() {
            ResponseEntity<ResponseMessage> response = endpoint.resetPassword(resetPasswordRequest);

            assertNotNull(response.getBody());
            assertEquals(userProfile, ((SuccessResponseMessage<?>) response.getBody()).getData());
        }
    }

}