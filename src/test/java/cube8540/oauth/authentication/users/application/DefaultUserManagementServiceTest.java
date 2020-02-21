package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserAlreadyExistsException;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 계정 관리 서비스 테스트")
class DefaultUserManagementServiceTest {

    private static final String RAW_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final String RAW_PASSWORD = "Password1234!@#$";

    private static final String ENCODING_PASSWORD = "$2a$10$MrsAcjEPfD4ktbWEb13SBu.lE2OfGWZ2NPqgUoSTeWA7bvh9.k3WC";

    private static final LocalDateTime REGISTERED_AT = LocalDateTime.of(2020, 2, 8, 15, 38);

    private PasswordEncoder encoder;
    private UserRepository userRepository;
    private DefaultUserManagementService service;

    @BeforeEach
    void setup() {
        this.userRepository = mock(UserRepository.class);
        this.encoder = mock(PasswordEncoder.class);
        this.service = new DefaultUserManagementService(userRepository, encoder);
    }

    @Nested
    @DisplayName("유저 카운팅")
    class UserCounting {
        private long randomCount;

        @BeforeEach
        void setup() {
            this.randomCount = (long) (Math.random() * 100);
            when(userRepository.countByEmail(EMAIL)).thenReturn(randomCount);
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
        class WhenUserNotFound {

            @BeforeEach
            void setup() {
                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("UserNotFoundException이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.loadUserProfile(RAW_EMAIL));
            }
        }
    }

    @Nested
    @DisplayName("유저 등록")
    class RegisterUser {

        private UserRegisterRequest registerRequest;

        @BeforeEach
        void setup() {
            this.registerRequest = new UserRegisterRequest(RAW_EMAIL, RAW_PASSWORD);
        }

        @Nested
        @DisplayName("저장소에 이미 저장된 유저 이메일일시")
        class WhenExistingEmailInRepository {

            @BeforeEach
            void setup() {
                when(userRepository.countByEmail(new UserEmail(RAW_EMAIL))).thenReturn(1L);
            }

            @Test
            @DisplayName("UserAlreadyExistsException이 발생해야 한다.")
            void shouldThrowsUserAlreadyExistsException() {
                assertThrows(UserAlreadyExistsException.class, () -> service.registerUser(registerRequest));
            }
        }

        @Nested
        @DisplayName("저장소에 저장되지 않은 유저일시")
        class WhenNotRegisterInRepository {

            private ValidationRule<User> emailRule;
            private ValidationRule<User> passwordRule;

            @BeforeEach
            @SuppressWarnings("unchecked")
            void setup() {
                UserValidationPolicy policy = mock(UserValidationPolicy.class);
                this.emailRule = mock(ValidationRule.class);
                this.passwordRule = mock(ValidationRule.class);

                when(policy.emailRule()).thenReturn(emailRule);
                when(policy.passwordRule()).thenReturn(passwordRule);
                when(userRepository.countByEmail(new UserEmail(RAW_EMAIL))).thenReturn(0L);
                when(encoder.encode(RAW_PASSWORD)).thenReturn(ENCODING_PASSWORD);
                when(emailRule.isValid(any(User.class))).thenReturn(true);
                when(passwordRule.isValid(any(User.class))).thenReturn(true);

                doAnswer(returnsFirstArg()).when(userRepository).save(isA(User.class));

                service.setValidationPolicy(policy);
            }

            @Test
            @DisplayName("요청 받은 유저 이메일을 유효성 검사 후 저장해야 한다.")
            void shouldSaveRequestingUserEmailAfterValidation() {
                ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
                InOrder inOrder = inOrder(emailRule, userRepository);

                service.registerUser(registerRequest);
                inOrder.verify(emailRule, times(1)).isValid(userCaptor.capture());
                inOrder.verify(userRepository, times(1)).save(userCaptor.capture());
                assertEquals(userCaptor.getAllValues().get(0), userCaptor.getAllValues().get(1));
                assertEquals(EMAIL, userCaptor.getValue().getEmail());
            }

            @Test
            @DisplayName("요청 받은 유저 패스워드 유효성 검사 후 암호화 하여 저장해야 한다.")
            void shouldSaveEncodedRequestingUserPasswordAfterValidation() {
                ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
                InOrder inOrder = inOrder(passwordRule, userRepository);

                service.registerUser(registerRequest);
                inOrder.verify(passwordRule, times(1)).isValid(userCaptor.capture());
                inOrder.verify(userRepository, times(1)).save(userCaptor.capture());
                assertEquals(userCaptor.getAllValues().get(0), userCaptor.getAllValues().get(1));
                assertEquals(ENCODING_PASSWORD, userCaptor.getValue().getPassword());
            }
        }
    }

    @Nested
    @DisplayName("유저 삭제")
    class RemoveUser {

        @Nested
        @DisplayName("저장소에 저장되있지 않은 유저일시")
        class WhenNotRegisterUserInRepository {

            @BeforeEach
            void setup() {
                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("UserNotFoundExceptio이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.removeUser(RAW_EMAIL));
            }
        }

        @Nested
        @DisplayName("저장소에 저장되어있는 유저일시")
        class WhenRegisterUserInRepository {
            private User user;

            @BeforeEach
            void setup() {
                this.user = mock(User.class);

                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
                when(user.getEmail()).thenReturn(EMAIL);
                when(user.getRegisteredAt()).thenReturn(REGISTERED_AT);
            }

            @Test
            @DisplayName("유저를 저장소에서 삭제해야 한다.")
            void shouldRemoveUserToRepository() {
                ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

                service.removeUser(RAW_EMAIL);
                verify(userRepository, times(1)).delete(userCaptor.capture());
                assertEquals(user, userCaptor.getValue());
            }
        }
    }
}