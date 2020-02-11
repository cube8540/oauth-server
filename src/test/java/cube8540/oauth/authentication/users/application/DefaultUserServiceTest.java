package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 서비스 테스트")
class DefaultUserServiceTest {

    private UserRepository repository;
    private DefaultUserService service;

    private User user;

    @BeforeEach
    void setup() {
        this.user = mock(User.class);
        this.repository = mock(UserRepository.class);
        this.service = new DefaultUserService(repository);
    }

    @Nested
    @DisplayName("저장소의 유저를 로딩")
    class WhenLoadingUser {
        private UserEmail email = new UserEmail("email@email.com");
        private String password = "password";
        private Set<AuthorityCode> authorityCodes = new HashSet<>(Arrays.asList(
                new AuthorityCode("CODE-1"), new AuthorityCode("CODE-2"), new AuthorityCode("CODE-3")));

        @BeforeEach
        void setup() {
            when(user.getEmail()).thenReturn(email);
            when(user.getPassword()).thenReturn(password);
            when(user.getAuthorities()).thenReturn(authorityCodes);
            when(repository.findByEmail(any())).thenReturn(Optional.empty());
        }

        @Nested
        @DisplayName("저장소에 유저가 없을시")
        class WhenNotFoundUser {

            @Test
            @DisplayName("UsernameNotFoundException이 발생해야 한다.")
            void shouldThrowsUsernameNotFoundException() {
                assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername("email@email.com"));
            }
        }

        @Nested
        @DisplayName("저장소에 유저가 있을시")
        class WhenFoundUser {

            @BeforeEach
            void setup() {
                when(repository.findByEmail(email)).thenReturn(Optional.of(user));
            }

            @Test
            @DisplayName("저장소에서 찾은 유저의 이메일을 반환해야 한다.")
            void shouldReturnsUserEmail() {
                UserDetails result = service.loadUserByUsername("email@email.com");

                assertEquals("email@email.com", result.getUsername());
            }

            @Test
            @DisplayName("저장소에서 찾은 유저의 패스워드를 반환해야 한다.")
            void shouldReturnsUserPassword() {
                UserDetails result = service.loadUserByUsername("email@email.com");

                assertEquals("password", result.getPassword());
            }

            @Test
            @DisplayName("저장소에서 찾은 유저의 권한을 반환해야 한다.")
            void shouldReturnsGrantedAuthority() {
                UserDetails result = service.loadUserByUsername("email@email.com");

                Set<GrantedAuthority> expectedAuthorities = authorityCodes.stream()
                        .map(auth -> new SimpleGrantedAuthority(auth.getValue()))
                        .collect(Collectors.toSet());
                assertEquals(expectedAuthorities, result.getAuthorities());
            }

            @Nested
            @DisplayName("찾은 유저가 인증을 받지 않았을시")
            class WhenFindUserIsNotCredentials {

                @BeforeEach
                void setup() {
                    when(user.getAuthorities()).thenReturn(null);
                }

                @Test
                @DisplayName("계정의 잠금된 설정으로 반환되어야 한다.")
                void shouldAccountIsNotLocked() {
                    UserDetails result = service.loadUserByUsername("email@email.com");

                    boolean nonLocked = result.isAccountNonLocked();
                    assertFalse(nonLocked);
                }
            }

            @Nested
            @DisplayName("찾은 유저가 인증을 받았을시")
            class WhenFindUserIsCredentials {

                @Test
                @DisplayName("계정의 잠금되지 않은 설정으로 반환되어야 한다.")
                void shouldAccountIsNotLocked() {
                    UserDetails result = service.loadUserByUsername("email@email.com");

                    boolean nonLocked = result.isAccountNonLocked();
                    assertTrue(nonLocked);
                }
            }
        }
    }

}