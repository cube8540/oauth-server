package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.credentials.authority.application.BasicAuthorityService;
import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.error.UserNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.BASIC_AUTHORITIES;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_CREDENTIALS_KEY;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_EMAIL;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.configDefaultMockUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockBasicAuthorityService;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockKeyGenerator;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.mockUserRepository;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 유저 인증 서비스 테스트")
class DefaultUserCredentialsServiceTest {

    @Nested
    @DisplayName("유저 인증키 할당")
    class UserGrantCredentialsKey {

        @Nested
        @DisplayName("인증키를 할당할 유저가 저장소에 등록되지 않았을시")
        class WhenUserNotRegisteredInRepository extends UserNotFoundSetup {

            @Test
            @DisplayName("UserNotFoundException 이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.grantCredentialsKey(RAW_EMAIL));
            }
        }

        @Nested
        @DisplayName("인증키를 할당할 유저가 저장소에 등록되어 있을시")
        class WhenUserRegisteredInRepository {
            private User user;
            private UserRepository repository;
            private UserCredentialsKeyGenerator keyGenerator;

            private DefaultUserCredentialsService service;

            @BeforeEach
            void setup() {
                this.user = configDefaultMockUser().build();
                this.repository = mockUserRepository().registerUser(user).build();
                this.keyGenerator = mockKeyGenerator();

                this.service = new DefaultUserCredentialsService(repository, mockBasicAuthorityService().build());
                this.service.setKeyGenerator(keyGenerator);
            }

            @Test
            @DisplayName("검색된 유저에게 인증키를 할당해야 한다.")
            void shouldGrantCredentialsKeyForUser() {
                service.grantCredentialsKey(RAW_EMAIL);

                verify(user, times(1)).generateCredentialsKey(keyGenerator);
            }

            @Test
            @DisplayName("검색된 유저에게 인증키를 할당한 후 저장소에 저장해야 한다")
            void shouldSaveUserForRepositoryAfterGrantCredentialsKey() {
                service.grantCredentialsKey(RAW_EMAIL);

                InOrder inOrder = inOrder(user, repository);
                inOrder.verify(user, times(1)).generateCredentialsKey(keyGenerator);
                inOrder.verify(repository, times(1)).save(user);
            }
        }
    }

    @Nested
    @DisplayName("계정 인증")
    class AccountCredentials {

        @Nested
        @DisplayName("유저가 저장소에 등록되지 않았을시")
        class WhenUserNotRegisteredInRepository extends UserNotFoundSetup {

            @Test
            @DisplayName("UserNotFoundException 이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.accountCredentials(RAW_EMAIL, RAW_CREDENTIALS_KEY));
            }
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있을시")
        class WhenUserRegisteredInRepository {
            private User user;
            private UserRepository repository;

            private DefaultUserCredentialsService service;

            @BeforeEach
            void setup() {
                this.user = configDefaultMockUser().build();
                this.repository = mockUserRepository().registerUser(user).build();

                BasicAuthorityService basicAuthorityService = mockBasicAuthorityService().basicAuthority().build();

                this.service = new DefaultUserCredentialsService(repository, basicAuthorityService);
            }

            @Test
            @DisplayName("요청 받은 인증키와 기본 권한으로 계정 인증을 해야 한다.")
            void shouldAccountCredentialsByRequestingCredentialsKeyAndBasicAuthority() {
                service.accountCredentials(RAW_EMAIL, RAW_CREDENTIALS_KEY);

                verify(user, times(1)).credentials(RAW_CREDENTIALS_KEY, BASIC_AUTHORITIES);
            }

            @Test
            @DisplayName("계정 인증후 저장소에 저장해야 한다.")
            void shouldSaveUserForRepositoryAfterAccountCredentials() {
                service.accountCredentials(RAW_EMAIL, RAW_CREDENTIALS_KEY);

                InOrder inOrder = inOrder(user, repository);
                inOrder.verify(user, times(1)).credentials(RAW_CREDENTIALS_KEY, BASIC_AUTHORITIES);
                inOrder.verify(repository, times(1)).save(user);
            }
        }
    }

    abstract static class UserNotFoundSetup {
        protected DefaultUserCredentialsService service;

        @BeforeEach
        void setup() {
            UserRepository repository = mockUserRepository().emptyUser().build();

            this.service = new DefaultUserCredentialsService(repository, mockBasicAuthorityService().build());
        }
    }
}