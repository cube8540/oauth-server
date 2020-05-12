package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("기본 유저 서비스 테스트")
class DefaultUserServiceTest {

    @Nested
    @DisplayName("저장소의 유저를 로딩")
    class WhenLoadingUser {

        @Nested
        @DisplayName("저장소에 유저가 없을시")
        class WhenNotRegisteredUserInRepository {
            private DefaultUserService service;

            @BeforeEach
            void setup() {
                UserRepository repository = UserApplicationTestHelper.mockUserRepository().emptyUser().build();
                this.service = new DefaultUserService(repository);
            }

            @Test
            @DisplayName("UsernameNotFoundException 이 발생해야 한다.")
            void shouldThrowsUsernameNotFoundException() {
                assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername(UserApplicationTestHelper.RAW_EMAIL));
            }
        }

        @Nested
        @DisplayName("저장소에 유저가 있을시")
        class WhenRegisteredUserInRepository {

            @Nested
            @DisplayName("등록된 유저가 인증을 받지 않은 상태일시")
            class WhenRegisteredUserIsNotCertified {
                private DefaultUserService service;

                @BeforeEach
                void setup() {
                    User user = UserApplicationTestHelper.configDefaultMockUser().build();
                    UserRepository repository = UserApplicationTestHelper.mockUserRepository().registerUser(user).build();
                    this.service = new DefaultUserService(repository);
                }

                @Test
                @DisplayName("계정의 잠금된 설정으로 반환되어야 한다.")
                void shouldAccountIsNotLocked() {
                    UserDetails result = service.loadUserByUsername(UserApplicationTestHelper.RAW_EMAIL);

                    assertFalse(result.isAccountNonLocked());
                }
            }

            @Nested
            @DisplayName("등록된 유저가 인증을 받은 상태일시")
            class WhenRegisteredUserIsCertified {
                private DefaultUserService service;

                @BeforeEach
                void setup() {
                    User user = UserApplicationTestHelper.configDefaultMockUser().certified().build();
                    UserRepository repository = UserApplicationTestHelper.mockUserRepository().registerUser(user).build();
                    this.service = new DefaultUserService(repository);
                }

                @Test
                @DisplayName("권한은 항상 빈 배열로 반환 해야 한다.")
                void shouldReturnEmptyArrayToAuthority() {
                    UserDetails result = service.loadUserByUsername(UserApplicationTestHelper.RAW_EMAIL);

                    assertEquals(Collections.emptySet(), result.getAuthorities());
                }

                @Test
                @DisplayName("계정의 잠금되지 않은 설정으로 반환되어야 한다.")
                void shouldAccountIsNotLocked() {
                    UserDetails result = service.loadUserByUsername(UserApplicationTestHelper.RAW_EMAIL);

                    assertTrue(result.isAccountNonLocked());
                }
            }
        }
    }

}