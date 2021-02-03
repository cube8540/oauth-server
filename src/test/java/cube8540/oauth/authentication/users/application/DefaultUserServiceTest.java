package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;

import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeCertifiedUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeEmptyUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeNotCertifiedUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeUserRepository;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("기본 유저 서비스 테스트")
class DefaultUserServiceTest {

    @Test
    @DisplayName("저장소에 저장 되지 않은 유저 로딩")
    void loadUserNotRegisteredInRepository() {
        UserRepository repository = makeEmptyUserRepository();

        DefaultUserService service = new DefaultUserService(repository);

        assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername(RAW_USERNAME));
    }

    @Test
    @DisplayName("인증 받지 못한 유저 로딩")
    void loadNotCertifiedUser() {
        User user = makeNotCertifiedUser();
        UserRepository repository = makeUserRepository(USERNAME, user);

        DefaultUserService service = new DefaultUserService(repository);

        UserDetails result = service.loadUserByUsername(RAW_USERNAME);
        assertFalse(result.isAccountNonLocked());
    }

    @Test
    @DisplayName("인증된 유저 로딩")
    void loadCertifiedUser() {
        User user = makeCertifiedUser();
        UserRepository repository = makeUserRepository(USERNAME, user);

        DefaultUserService service = new DefaultUserService(repository);

        UserDetails result = service.loadUserByUsername(RAW_USERNAME);
        assertEquals(Collections.emptyList(), result.getAuthorities());
        assertTrue(result.isAccountNonLocked());
    }
}