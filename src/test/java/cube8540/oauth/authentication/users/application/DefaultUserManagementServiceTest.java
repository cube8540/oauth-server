package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
import cube8540.oauth.authentication.users.error.UserErrorCodes;
import cube8540.oauth.authentication.users.error.UserNotFoundException;
import cube8540.oauth.authentication.users.error.UserRegisterException;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.EMAIL;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.ENCODED_PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.PASSWORD;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_EMAIL;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.configDefaultMockUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockPasswordEncoder;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockValidationPolicy;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockValidationRule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 유저 계정 관리 서비스 테스트")
class DefaultUserManagementServiceTest {

    @Nested
    @DisplayName("유저 카운팅")
    class UserCounting {
        private long randomCount;
        private DefaultUserManagementService service;

        @BeforeEach
        void setup() {
            this.randomCount = (long) (Math.random() * 100);

            UserRepository repository = mockUserRepository().countUser(randomCount).build();

            this.service = new DefaultUserManagementService(repository, mockPasswordEncoder().build());
        }

        @Test
        @DisplayName("저장소에서 검색된 유저의 카운터를 반환해야 한다.")
        void shouldReturnsUserCount() {
            long count = service.countUser(RAW_EMAIL);

            assertEquals(randomCount, count);
        }
    }

    @Nested
    @DisplayName("유저 프로필 검색")
    class LoadUserProfile {

        @Nested
        @DisplayName("찾고 싶은 유저가 저장소에 없을시")
        class WhenNotRegisteredUserInRepository extends UserNotFoundSetup {

            @Test
            @DisplayName("UserNotFoundException 이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.loadUserProfile(RAW_EMAIL));
            }
        }
    }

    @Nested
    @DisplayName("유저 등록")
    class RegisterUser {

        @Nested
        @DisplayName("저장소에 이미 저장된 유저 이메일일시")
        class WhenExistingEmailInRepository {
            private UserRegisterRequest registerRequest;

            private DefaultUserManagementService service;

            @BeforeEach
            void setup() {
                UserRepository repository = mockUserRepository().countUser(1L).build();

                this.registerRequest = new UserRegisterRequest(RAW_EMAIL, PASSWORD);
                this.service = new DefaultUserManagementService(repository, mockPasswordEncoder().build());
            }

            @Test
            @DisplayName("에러가 발생해야 하며, 에러 코드는 EXISTS_IDENTIFIER 이어야 한다.")
            void shouldThrowsErrorAndErrorCodeIsExistsIdentifier() {
                UserRegisterException e = assertThrows(UserRegisterException.class, () -> service.registerUser(registerRequest));
                assertEquals(UserErrorCodes.EXISTS_IDENTIFIER, e.getCode());
            }
        }

        @Nested
        @DisplayName("저장소에 저장되지 않은 유저일시")
        class WhenNotRegisterInRepository {
            private UserRepository repository;
            private ValidationRule<User> emailRule;
            private ValidationRule<User> passwordRule;

            private UserRegisterRequest registerRequest;

            private DefaultUserManagementService service;

            @BeforeEach
            void setup() {
                this.repository = mockUserRepository().countUser(0).build();
                this.emailRule = mockValidationRule().configReturnsTrue().build();
                this.passwordRule = mockValidationRule().configReturnsTrue().build();

                UserValidationPolicy policy = mockValidationPolicy()
                        .email(emailRule).password(passwordRule).build();
                PasswordEncoder encoder = mockPasswordEncoder().encode().build();

                this.service = new DefaultUserManagementService(repository, encoder);
                this.service.setValidationPolicy(policy);

                this.registerRequest = new UserRegisterRequest(RAW_EMAIL, PASSWORD);
            }

            @Test
            @DisplayName("요청 받은 유저 이메일을 유효성 검사를 해야 한다.")
            void shouldSaveRequestingUserEmailAfterValidation() {
                ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

                service.registerUser(registerRequest);
                verifySaveAfterValidation(emailRule, userCaptor);
                assertEquals(EMAIL, userCaptor.getValue().getEmail());
            }

            @Test
            @DisplayName("요청 받은 유저 패스워드 유효성 검사 후 암호화 하여 저장해야 한다.")
            void shouldSaveEncodedRequestingUserPasswordAfterValidation() {
                ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

                service.registerUser(registerRequest);
                verifySaveAfterValidation(passwordRule, userCaptor);
                assertEquals(ENCODED_PASSWORD, userCaptor.getValue().getPassword());
            }

            private void verifySaveAfterValidation(ValidationRule<User> rule, ArgumentCaptor<User> argumentCaptor) {
                InOrder inOrder = inOrder(rule, repository);
                inOrder.verify(rule, times(1)).isValid(argumentCaptor.capture());
                inOrder.verify(repository, times(1)).save(argumentCaptor.capture());
                assertEquals(argumentCaptor.getAllValues().get(0), argumentCaptor.getAllValues().get(1));
            }
        }
    }

    @Nested
    @DisplayName("유저 삭제")
    class RemoveUser {

        @Nested
        @DisplayName("저장소에 저장되있지 않은 유저일시")
        class WhenNotRegisterUserInRepository extends UserNotFoundSetup {

            @Test
            @DisplayName("UserNotFoundException 이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.removeUser(RAW_EMAIL));
            }
        }

        @Nested
        @DisplayName("저장소에 저장되어있는 유저일시")
        class WhenRegisterUserInRepository {
            private User user;
            private UserRepository repository;

            private UserManagementService service;

            @BeforeEach
            void setup() {
                this.user = configDefaultMockUser().build();
                this.repository = mockUserRepository().registerUser(user).build();

                this.service = new DefaultUserManagementService(repository, mockPasswordEncoder().build());
            }

            @Test
            @DisplayName("유저를 저장소에서 삭제해야 한다.")
            void shouldRemoveUserToRepository() {
                ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

                service.removeUser(RAW_EMAIL);
                verify(repository, times(1)).delete(userCaptor.capture());
                assertEquals(user, userCaptor.getValue());
            }
        }
    }

    abstract static class UserNotFoundSetup {
        protected DefaultUserManagementService service;

        @BeforeEach
        void setup() {
            UserRepository repository = mockUserRepository().emptyUser().build();

            this.service = new DefaultUserManagementService(repository, mockPasswordEncoder().build());
        }
    }
}