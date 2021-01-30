package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.ApprovalAuthority;
import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserRepository;
import cube8540.oauth.authentication.users.domain.UserValidatorFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.util.Collection;
import java.util.Set;

import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.AUTHORITIES_A;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeComposeApprovalAuthorities;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeDefaultUser;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeEmptyUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeUserRepository;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeValidatorFactory;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.when;

@DisplayName("유저 기본 승인 권한 서비스")
public class DefaultUserApprovalAuthorityServiceTest {

    @Test
    @DisplayName("유저를 찾을 수 없을때 유저 승인 권한 검색")
    void getApprovalAuthoritiesWhenUserNotFound() {
        UserRepository repository = makeEmptyUserRepository();

        DefaultUserApprovalAuthorityService service = new DefaultUserApprovalAuthorityService(repository);

        assertThrows(UserNotFoundException.class, () -> service.getApprovalAuthorities(RAW_USERNAME));
    }

    @Test
    @DisplayName("유저를 찾으면 그 유저의 승인 권한을 반환 해야 한다.")
    void ifUserFoundReturnsFoundedUsersApprovalAuthorities() {
        User user = makeDefaultUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        Set<ApprovalAuthority> approvalAuthorities = makeComposeApprovalAuthorities();
        DefaultUserApprovalAuthorityService service = new DefaultUserApprovalAuthorityService(repository);

        when(user.getApprovalAuthorities()).thenReturn(approvalAuthorities);

        Collection<ApprovalAuthority> results = service.getApprovalAuthorities(RAW_USERNAME);
        assertEquals(approvalAuthorities, results);
    }

    @Test
    @DisplayName("찾을 수 없는 유저에게 승인 권한을 추가 했을시")
    void grantApprovalAuthoritiesToNotFoundUser() {
        UserRepository repository = makeEmptyUserRepository();
        DefaultUserApprovalAuthorityService service = new DefaultUserApprovalAuthorityService(repository);

        assertThrows(UserNotFoundException.class, () -> service.grantApprovalAuthorities(RAW_USERNAME, AUTHORITIES_A));
    }

    @Test
    @DisplayName("승인 권한을 추가")
    void grantNotAllowApprovalAuthorities() {
        User user = makeDefaultUser();
        UserValidatorFactory factory = makeValidatorFactory();
        UserRepository repository = makeUserRepository(USERNAME, user);
        DefaultUserApprovalAuthorityService service = new DefaultUserApprovalAuthorityService(repository);

        service.setValidatorFactory(factory);

        service.grantApprovalAuthorities(RAW_USERNAME, AUTHORITIES_A);
        InOrder inOrder = inOrder(user, repository);
        AUTHORITIES_A.forEach(authority -> inOrder.verify(user)
                .addApprovalAuthority(authority.getClientId(), authority.getScopeId()));
        inOrder.verify(user).validation(factory);
        inOrder.verify(repository).save(user);
    }

    @Test
    @DisplayName("찾을 수 없는 유저의 승인 권한 삭제")
    void revokeApprovalAuthoritiesToNotFoundUser() {
        UserRepository repository = makeEmptyUserRepository();
        DefaultUserApprovalAuthorityService service = new DefaultUserApprovalAuthorityService(repository);

        assertThrows(UserNotFoundException.class, () -> service.revokeApprovalAuthorities(RAW_USERNAME, AUTHORITIES_A));
    }

    @Test
    @DisplayName("승인 권한 삭제")
    void revokeApprovalAuthorities() {
        User user = makeDefaultUser();
        UserRepository repository = makeUserRepository(USERNAME, user);
        DefaultUserApprovalAuthorityService service = new DefaultUserApprovalAuthorityService(repository);

        service.revokeApprovalAuthorities(RAW_USERNAME, AUTHORITIES_A);
        InOrder inOrder = inOrder(user, repository);
        AUTHORITIES_A.forEach(authority -> inOrder.verify(user)
                .revokeApprovalAuthority(authority.getClientId(), authority.getScopeId()));
        inOrder.verify(repository).save(user);
    }
}
