package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.credentials.authority.application.BasicAuthorityService;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 인증 서비스 테스트")
class DefaultUserCredentialsServiceTest {

    private static final String RAW_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final LocalDateTime REGISTERED_AT = LocalDateTime.of(2020, 2, 8, 19, 24);

    private static final String RAW_CREDENTIALS_KEY = "KEY";

    private UserRepository userRepository;
    private BasicAuthorityService authorityService;
    private UserCredentialsKeyGenerator keyGenerator;
    private DefaultUserCredentialsService service;

    @BeforeEach
    void setup() {
        this.userRepository = mock(UserRepository.class);
        this.authorityService = mock(BasicAuthorityService.class);
        this.keyGenerator = mock(UserCredentialsKeyGenerator.class);

        this.service = new DefaultUserCredentialsService(userRepository, authorityService);
        this.service.setKeyGenerator(keyGenerator);
    }

    @Nested
    @DisplayName("유저 인증키 할당")
    class UserGrantCredentialsKey {

        @Nested
        @DisplayName("인증키를 할당할 유저가 저장소에 등록되지 않았을시")
        class WhenUserNotRegisterInRepository {

            @BeforeEach
            void setup() {
                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("UserNotFoundException이 발생해야 한다.")
            void shouldThrowsUserNotFoundException() {
                assertThrows(UserNotFoundException.class, () -> service.grantCredentialsKey(RAW_EMAIL));
            }
        }

        @Nested
        @DisplayName("인증키를 할당할 유저가 저장소에 등록되어 있을시")
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
            @DisplayName("검색된 유저에게 인증키를 할당해야 한다.")
            void shouldGrantCredentialsKeyForUser() {
                service.grantCredentialsKey(RAW_EMAIL);

                verify(user, times(1)).generateCredentialsKey(keyGenerator);
            }

            @Test
            @DisplayName("검색된 유저에게 인증키를 할당한 후 저장소에 저장해야 한다")
            void shouldSaveUserForRepositoryAfterGrantCredentialsKey() {
                service.grantCredentialsKey(RAW_EMAIL);

                InOrder inOrder = inOrder(user, userRepository);
                inOrder.verify(user, times(1)).generateCredentialsKey(keyGenerator);
                inOrder.verify(userRepository, times(1)).save(user);
            }
        }
    }

    @Nested
    @DisplayName("계정 인증")
    class AccountCredentials {

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
                assertThrows(UserNotFoundException.class, () -> service.accountCredentials(RAW_EMAIL, RAW_CREDENTIALS_KEY));
            }
        }

        @Nested
        @DisplayName("유저가 저장소에 등록되어 있을시")
        class WhenUserRegisterInRepository {

            private User user;
            private List<AuthorityCode> basicAuthority;

            @BeforeEach
            void setup() {
                this.user = mock(User.class);
                this.basicAuthority = Arrays.asList(new AuthorityCode("CODE-1"),
                        new AuthorityCode("CODE-2"), new AuthorityCode("CODE-3"));

                when(user.getEmail()).thenReturn(EMAIL);
                when(user.getRegisteredAt()).thenReturn(REGISTERED_AT);
                when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
                when(authorityService.getBasicAuthority()).thenReturn(basicAuthority);

                doAnswer(returnsFirstArg()).when(userRepository).save(isA(User.class));
            }

            @Test
            @DisplayName("요청 받은 인증키와 기본 권한으로 계정 인증을 해야 한다.")
            void shouldAccountCredentialsByRequestingCredentialsKeyAndBasicAuthority() {
                service.accountCredentials(RAW_EMAIL, RAW_CREDENTIALS_KEY);

                verify(user, times(1)).credentials(RAW_CREDENTIALS_KEY, basicAuthority);
            }

            @Test
            @DisplayName("계정 인증후 저장소에 저장해야 한다.")
            void shouldSaveUserForRepositoryAfterAccountCredentials() {
                service.accountCredentials(RAW_EMAIL, RAW_CREDENTIALS_KEY);

                InOrder inOrder = inOrder(user, userRepository);
                inOrder.verify(user, times(1)).credentials(RAW_CREDENTIALS_KEY, basicAuthority);
                inOrder.verify(userRepository, times(1)).save(user);
            }
        }
    }
}