package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKey;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserKeyMatchedResult;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserPasswordEncoder;
import cube8540.oauth.authentication.users.domain.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 패스워드 서비스 테스트")
class DefaultUserPasswordServiceTest {

    private static final String RAW_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final String RAW_EXISTING_PASSWORD = "Password1234!@#$";
    private static final String RAW_NEW_PASSWORD = "NewPassword1234!@#$";

    private static final LocalDateTime REGISTERED_AT = LocalDateTime.of(2020, 2, 8, 19, 24);

    private static final String RAW_CREDENTIALS_KEY = "KEY";

    private UserRepository userRepository;
    private UserPasswordEncoder encoder;
    private UserCredentialsKeyGenerator keyGenerator;
    private DefaultUserPasswordService service;

    @BeforeEach
    void setup() {
        this.userRepository = mock(UserRepository.class);
        this.encoder = mock(UserPasswordEncoder.class);
        this.keyGenerator = mock(UserCredentialsKeyGenerator.class);

        this.service = new DefaultUserPasswordService(userRepository, encoder, keyGenerator);
    }

    @Nested
    @DisplayName("패스워드 변경")
    class ChangePassword {

        private ChangePasswordRequest changeRequest;

        @BeforeEach
        void setup() {
            this.changeRequest = new ChangePasswordRequest(RAW_EMAIL, RAW_EXISTING_PASSWORD, RAW_NEW_PASSWORD);
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되지 않았을시")
        class WhenUserNotRegisterInRepository {

            @BeforeEach
            void setup() {
                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("UserNotFoundException이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.changePassword(changeRequest));
            }
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있을시")
        class WhenUserRegisterInRepository {

            private User user;
            private ChangePasswordRequest changeRequest;

            @BeforeEach
            void setup() {
                this.user = mock(User.class);
                this.changeRequest = new ChangePasswordRequest(RAW_EMAIL, RAW_EXISTING_PASSWORD, RAW_NEW_PASSWORD);

                when(user.getEmail()).thenReturn(EMAIL);
                when(user.getRegisteredAt()).thenReturn(REGISTERED_AT);
                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

                doAnswer(returnsFirstArg()).when(userRepository).save(isA(User.class));
            }

            @Test
            @DisplayName("유저의 패스워드를 변경해야 한다.")
            void shouldChangeUserPassword() {
                service.changePassword(changeRequest);

                verify(user, times(1)).changePassword(RAW_EXISTING_PASSWORD, RAW_NEW_PASSWORD, encoder);
            }

            @Test
            @DisplayName("유저의 패스워드를 변경한 후 저장소에 저장해야 한다.")
            void shouldSaveUserForRepositoryAfterPasswordChanged() {
                service.changePassword(changeRequest);

                InOrder inOrder = inOrder(user, userRepository);
                inOrder.verify(user, times(1)).changePassword(RAW_EXISTING_PASSWORD, RAW_NEW_PASSWORD, encoder);
                inOrder.verify(userRepository, times(1)).save(user);
            }

            @Test
            @DisplayName("패스워드를 변경한 유저의 이메일을 반환해야 한다.")
            void shouldReturnsUserEmail() {
                UserProfile profile = service.changePassword(changeRequest);

                assertEquals(RAW_EMAIL, profile.getEmail());
            }

            @Test
            @DisplayName("패스워드를 변경한 유저의 등록일을 반환해야 한다.")
            void shouldReturnsUserRegisteredAt() {
                UserProfile profile = service.changePassword(changeRequest);

                assertEquals(REGISTERED_AT, profile.getRegisteredAt());
            }
        }
    }

    @Nested
    @DisplayName("유저 패스워드 분실 요청")
    class ForgotUserPassword {

        @Nested
        @DisplayName("유저가 저장소에 등록되지 않았을시")
        class WhenUserNotRegisterInRepository {

            @BeforeEach
            void setup() {
                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("UserNotFoundException이 발생해야한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.forgotPassword(RAW_EMAIL));
            }
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있을시")
        class WhenUserRegisterInRepository {

            private User user;

            @BeforeEach
            void setup() {
                this.user = mock(User.class);

                when(user.getEmail()).thenReturn(EMAIL);
                when(user.getRegisteredAt()).thenReturn(REGISTERED_AT);
                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

                doAnswer(returnsFirstArg()).when(userRepository).save(isA(User.class));
            }

            @Test
            @DisplayName("검색된 유저에게 패스워드 인증키를 할당해야 한다.")
            void shouldGeneratePasswordCredentialsKeyForUser() {
                service.forgotPassword(RAW_EMAIL);

                verify(user, times(1)).forgotPassword(keyGenerator);
            }

            @Test
            @DisplayName("패스워드 인증키를 할당한 후 저장소에 저장해야 한다.")
            void shouldSaveUserForRepositoryAfterGenerateCredentialsKey() {
                service.forgotPassword(RAW_EMAIL);

                InOrder inOrder = inOrder(user, userRepository);
                inOrder.verify(user, times(1)).forgotPassword(keyGenerator);
                inOrder.verify(userRepository, times(1)).save(user);
            }

            @Test
            @DisplayName("인증키를 할당 받은 유저의 이메일을 반환해야 한다.")
            void shouldReturnsUserEmail() {
                UserProfile profile = service.forgotPassword(RAW_EMAIL);

                assertEquals(RAW_EMAIL, profile.getEmail());
            }

            @Test
            @DisplayName("인증키를 할당 받은 유저의 등록일을 반환해야 한다.")
            void shouldReturnsUserRegisteredAt() {
                UserProfile profile = service.forgotPassword(RAW_EMAIL);

                assertEquals(REGISTERED_AT, profile.getRegisteredAt());
            }
        }
    }

    @Nested
    @DisplayName("인증키 검사")
    class ValidateCredentialsKey {

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있지 않을시")
        class WhenUserNotRegisterInRepository {

            @BeforeEach
            void setup() {
                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("UserNotFoundException이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.validateCredentialsKey(RAW_EMAIL, RAW_CREDENTIALS_KEY));
            }
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있을시")
        class WHenUserRegisterInRepository {

            private UserCredentialsKey key;

            @BeforeEach
            void setup() {
                User user = mock(User.class);
                this.key = mock(UserCredentialsKey.class);

                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
                when(user.getEmail()).thenReturn(EMAIL);
                when(user.getRegisteredAt()).thenReturn(REGISTERED_AT);
                when(user.getPasswordCredentialsKey()).thenReturn(key);
            }

            @Nested
            @DisplayName("이미 만료된 패스워드 인증키일시")
            class WhenPasswordCredentialsKeyExpired {

                @BeforeEach
                void setup() {
                    when(key.matches(RAW_CREDENTIALS_KEY)).thenReturn(UserKeyMatchedResult.EXPIRED);
                }

                @Test
                @DisplayName("검사 결과는 false여야 한다.")
                void shouldValidateResultIsFalse() {
                    boolean validate = service.validateCredentialsKey(RAW_EMAIL, RAW_CREDENTIALS_KEY);
                    assertFalse(validate);
                }
            }

            @Nested
            @DisplayName("서로 매칭되지 않는 키일시")
            class WhenNotMatchedKey {

                @BeforeEach
                void setup() {
                    when(key.matches(RAW_CREDENTIALS_KEY)).thenReturn(UserKeyMatchedResult.NOT_MATCHED);
                }

                @Test
                @DisplayName("검사 결과는 false여야 한다.")
                void shouldValidateResultIsFalse() {
                    boolean validate = service.validateCredentialsKey(RAW_EMAIL, RAW_CREDENTIALS_KEY);
                    assertFalse(validate);
                }
            }

            @Nested
            @DisplayName("서로 매칭되는 키일시")
            class WhenMatchedKey {

                @BeforeEach
                void setup() {
                    when(key.matches(RAW_CREDENTIALS_KEY)).thenReturn(UserKeyMatchedResult.MATCHED);
                }

                @Test
                @DisplayName("검삭 결과는 true여야 한다.")
                void shouldValidateResultIsTrue() {
                    boolean validate = service.validateCredentialsKey(RAW_EMAIL, RAW_CREDENTIALS_KEY);
                    assertTrue(validate);
                }
            }
        }
    }

    @Nested
    @DisplayName("패스워드 초기화")
    class ResetUserPassword {
        private ResetPasswordRequest request;

        @BeforeEach
        void setup() {
            this.request = new ResetPasswordRequest(RAW_EMAIL, RAW_CREDENTIALS_KEY, RAW_NEW_PASSWORD);
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되지 않았을시")
        class WhenUserNotRegisterInRepository {

            @BeforeEach
            void setup() {
                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("UserNotFoundException이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.resetPassword(request));
            }
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있을시")
        class WhenUserRegisterInRepository {

            private User user;

            @BeforeEach
            void setup() {
                this.user = mock(User.class);

                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
                when(user.getEmail()).thenReturn(EMAIL);
                when(user.getRegisteredAt()).thenReturn(REGISTERED_AT);

                doAnswer(returnsFirstArg()).when(userRepository).save(isA(User.class));
            }

            @Test
            @DisplayName("유저의 패스워드를 초기화 해야 한다.")
            void shouldResetPassword() {
                service.resetPassword(request);

                verify(user, times(1)).resetPassword(RAW_CREDENTIALS_KEY, RAW_NEW_PASSWORD, encoder);
            }

            @Test
            @DisplayName("유저의 패스워드를 초기화한 이후에 저장소에 저장해야 한다.")
            void shouldSaveUserForRepositoryAfterResetPassword() {
                service.resetPassword(request);

                InOrder inOrder = inOrder(user, userRepository);
                inOrder.verify(user, times(1)).resetPassword(RAW_CREDENTIALS_KEY, RAW_NEW_PASSWORD, encoder);
                inOrder.verify(userRepository, times(1)).save(user);
            }

            @Test
            @DisplayName("패스워드를 변경한 유저의 이메일을 반환해야 한다.")
            void shouldReturnsUserEmail() {
                UserProfile profile = service.resetPassword(request);

                assertEquals(RAW_EMAIL, profile.getEmail());
            }

            @Test
            @DisplayName("패스워드를 변경한 유저의 등록일을 반환해야 한다.")
            void shouldReturnsUserRegisteredAt() {
                UserProfile profile = service.resetPassword(request);

                assertEquals(REGISTERED_AT, profile.getRegisteredAt());
            }
        }
    }
}