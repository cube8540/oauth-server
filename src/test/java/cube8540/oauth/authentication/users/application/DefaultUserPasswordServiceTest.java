package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKey;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
import cube8540.oauth.authentication.users.domain.exception.UserNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.Principal;

import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.NEW_PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_EMAIL;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_PASSWORD_CREDENTIALS_KEY;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.configDefaultMockUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockCredentialsKey;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockKeyGenerator;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockPasswordEncoder;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockPrincipal;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockValidationPolicy;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 유저 패스워드 서비스 테스트")
class DefaultUserPasswordServiceTest {

    @Nested
    @DisplayName("패스워드 변경")
    class ChangePassword {

        @Nested
        @DisplayName("유저가 저장소에 등록되지 않았을시")
        class WhenUserNotRegisteredInRepository extends UserNotFoundSetup {

            @Test
            @DisplayName("UserNotFoundException 이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                Principal principal = mockPrincipal(RAW_EMAIL);
                ChangePasswordRequest changeRequest = new ChangePasswordRequest(PASSWORD, NEW_PASSWORD);

                assertThrows(UserNotFoundException.class, () -> service.changePassword(principal, changeRequest));
            }
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있을시")
        class WhenUserRegisterInRepository extends UserPasswordChangeableSetup {
            private Principal principal;
            private ChangePasswordRequest changeRequest;

            @BeforeEach
            void setupRequest() {
                this.principal = mockPrincipal(RAW_EMAIL);
                this.changeRequest = new ChangePasswordRequest(PASSWORD, NEW_PASSWORD);
            }

            @Test
            @DisplayName("유저의 패스워드를 변경해야 한다.")
            void shouldChangeUserPassword() {
                service.changePassword(principal, changeRequest);

                verify(user, times(1)).changePassword(PASSWORD, NEW_PASSWORD, encoder);
            }

            @Test
            @DisplayName("유저의 패스워드를 변경한 후 유효성 검사를 해야 한다.")
            void shouldValidationPasswordAfterChangeUserPassword() {
                service.changePassword(principal, changeRequest);

                InOrder inOrder = Mockito.inOrder(user);
                inOrder.verify(user, times(1)).changePassword(PASSWORD, NEW_PASSWORD, encoder);
                inOrder.verify(user, times(1)).validation(policy);
            }

            @Test
            @DisplayName("유저의 패스워드 유효성을 검사한 후 패스워드를 암호화 해야 한다.")
            void shouldPasswordEncryptingAfterChangeUserPasswordValidate() {
                service.changePassword(principal, changeRequest);

                InOrder inOrder = Mockito.inOrder(user);
                inOrder.verify(user, times(1)).validation(policy);
                inOrder.verify(user, times(1)).encrypted(encoder);
            }

            @Test
            @DisplayName("유저의 패스워드를 암호화 한 후 저장소에 저장해야 한다.")
            void shouldSaveUserForRepositoryAfterEncryptingPassword() {
                service.changePassword(principal, changeRequest);

                InOrder inOrder = inOrder(user, repository);
                inOrder.verify(user, times(1)).encrypted(encoder);
                inOrder.verify(repository, times(1)).save(user);
            }
        }
    }

    @Nested
    @DisplayName("유저 패스워드 분실 요청")
    class ForgotUserPassword {

        @Nested
        @DisplayName("유저가 저장소에 등록되지 않았을시")
        class WhenUserNotRegisterInRepository extends UserNotFoundSetup {

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
            private UserRepository repository;
            private DefaultUserPasswordService service;

            private UserCredentialsKeyGenerator keyGenerator;

            @BeforeEach
            void setup() {
                this.user = configDefaultMockUser().build();
                this.repository = mockUserRepository().registerUser(user).build();
                this.keyGenerator = mockKeyGenerator();

                this.service = new DefaultUserPasswordService(repository, mockPasswordEncoder().build());
                this.service.setKeyGenerator(keyGenerator);
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

                InOrder inOrder = inOrder(user, repository);
                inOrder.verify(user, times(1)).forgotPassword(keyGenerator);
                inOrder.verify(repository, times(1)).save(user);
            }
        }
    }

    @Nested
    @DisplayName("인증키 검사")
    class ValidateCredentialsKey {

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있지 않을시")
        class WhenUserNotRegisterInRepository extends UserNotFoundSetup {

            @Test
            @DisplayName("UserNotFoundException이 발생해야한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.forgotPassword(RAW_EMAIL));
            }
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있을시")
        class WhenUserRegisterInRepository extends UserPasswordChangeableSetup {

            @Nested
            @DisplayName("이미 만료된 패스워드 인증키일시")
            class PasswordCredentialsKeyIsExpired {
                private DefaultUserPasswordService service;

                @BeforeEach
                void setup() {
                    UserCredentialsKey key = mockCredentialsKey().expired().build();
                    User user = configDefaultMockUser().passwordCredentialsKey(key).build();

                    UserRepository repository = mockUserRepository().registerUser(user).build();

                    this.service = new DefaultUserPasswordService(repository, mockPasswordEncoder().build());
                    this.service.setKeyGenerator(mockKeyGenerator());
                }

                @Test
                @DisplayName("검사 결과는 false여야 한다.")
                void shouldValidateResultIsFalse() {
                    boolean validate = service.validateCredentialsKey(RAW_EMAIL, RAW_PASSWORD_CREDENTIALS_KEY);

                    assertFalse(validate);
                }
            }

            @Nested
            @DisplayName("서로 매칭되지 않는 키일시")
            class MismatchedCredentialsKey {
                private DefaultUserPasswordService service;

                @BeforeEach
                void setup() {
                    UserCredentialsKey key = mockCredentialsKey().mismatches().build();
                    User user = configDefaultMockUser().passwordCredentialsKey(key).build();

                    UserRepository repository = mockUserRepository().registerUser(user).build();

                    this.service = new DefaultUserPasswordService(repository, mockPasswordEncoder().build());
                    this.service.setKeyGenerator(mockKeyGenerator());
                }

                @Test
                @DisplayName("검사 결과는 false여야 한다.")
                void shouldValidateResultIsFalse() {
                    boolean validate = service.validateCredentialsKey(RAW_EMAIL, RAW_PASSWORD_CREDENTIALS_KEY);

                    assertFalse(validate);
                }
            }

            @Nested
            @DisplayName("서로 매칭되는 키일시")
            class MatchedCredentialsKey {
                private DefaultUserPasswordService service;

                @BeforeEach
                void setup() {
                    UserCredentialsKey key = mockCredentialsKey().matches().build();
                    User user = configDefaultMockUser().passwordCredentialsKey(key).build();

                    UserRepository repository = mockUserRepository().registerUser(user).build();

                    this.service = new DefaultUserPasswordService(repository, mockPasswordEncoder().build());
                    this.service.setKeyGenerator(mockKeyGenerator());
                }

                @Test
                @DisplayName("검삭 결과는 true여야 한다.")
                void shouldValidateResultIsTrue() {
                    boolean validate = service.validateCredentialsKey(RAW_EMAIL, RAW_PASSWORD_CREDENTIALS_KEY);

                    assertTrue(validate);
                }
            }
        }
    }

    @Nested
    @DisplayName("패스워드 초기화")
    class ResetUserPassword {

        @Nested
        @DisplayName("유저가 저장소에 등록되지 않았을시")
        class WhenUserNotRegisterInRepository extends UserNotFoundSetup {

            @Test
            @DisplayName("UserNotFoundException이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                ResetPasswordRequest request = new ResetPasswordRequest(RAW_EMAIL, RAW_PASSWORD_CREDENTIALS_KEY, NEW_PASSWORD);

                assertThrows(UserNotFoundException.class, () -> service.resetPassword(request));
            }
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있을시")
        class WhenUserRegisterInRepository extends UserPasswordChangeableSetup {
            private ResetPasswordRequest request;

            @BeforeEach
            void setupRequest() {
                this.request = new ResetPasswordRequest(RAW_EMAIL, RAW_PASSWORD_CREDENTIALS_KEY, NEW_PASSWORD);
            }

            @Test
            @DisplayName("유저의 패스워드를 초기화 해야 한다.")
            void shouldResetPassword() {
                service.resetPassword(request);

                verify(user, times(1)).resetPassword(RAW_PASSWORD_CREDENTIALS_KEY, NEW_PASSWORD);
            }

            @Test
            @DisplayName("유저의 패스워드를 초기화한 후 유효성 검사를 해야 한다.")
            void shouldValidationAfterResetUserPassword() {
                service.resetPassword(request);

                InOrder inOrder = inOrder(user);
                inOrder.verify(user, times(1)).resetPassword(RAW_PASSWORD_CREDENTIALS_KEY, NEW_PASSWORD);
                inOrder.verify(user, times(1)).validation(policy);
            }

            @Test
            @DisplayName("유저의 유효성을 검사한 후 패스워드를 암호화 해야 한다.")
            void shouldEncryptingPasswordAfterValidation() {
                service.resetPassword(request);

                InOrder inOrder = inOrder(user);
                inOrder.verify(user, times(1)).validation(policy);
                inOrder.verify(user, times(1)).encrypted(encoder);
            }

            @Test
            @DisplayName("유저의 패스워드를 암호화 한 후 저장소에 저장해야 한다.")
            void shouldSaveUserForRepositoryAfterEncryptingPassword() {
                service.resetPassword(request);

                InOrder inOrder = inOrder(user, repository);
                inOrder.verify(user, times(1)).encrypted(encoder);
                inOrder.verify(repository, times(1)).save(user);
            }
        }
    }

    private abstract static class UserNotFoundSetup {
        protected DefaultUserPasswordService service;

        @BeforeEach
        void setup() {
            UserRepository repository = mockUserRepository().emptyUser().build();
            this.service = new DefaultUserPasswordService(repository, mockPasswordEncoder().build());
        }
    }

    private abstract static class UserPasswordChangeableSetup {
        protected User user;
        protected UserRepository repository;
        protected PasswordEncoder encoder;
        protected UserValidationPolicy policy;

        protected DefaultUserPasswordService service;

        @BeforeEach
        void setup() {
            this.user = configDefaultMockUser().build();
            this.repository = mockUserRepository().registerUser(user).build();
            this.encoder = mockPasswordEncoder().encode().build();
            this.policy = mockValidationPolicy().build();

            this.service = new DefaultUserPasswordService(repository, encoder);
            this.service.setValidationPolicy(policy);
        }
    }
}