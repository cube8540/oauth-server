package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.users.domain.ApprovalAuthority;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.ALL_APPROVAL_SCOPES;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.AUTHORITIES_A;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.CLIENT_A_APPROVAL_AUTHORITIES;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.CLIENT_A_ID;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.REQUEST_SCOPES;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeAuthentication;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.users.application.UserApplicationTestHelper.makeComposeApprovalAuthorities;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("유저 자동 승인 스코프 헨들러 테스트")
public class UserAutoApprovalScopeHandlerTest {

    @Test
    @DisplayName("자동 승인 스코프 필터링")
    void filterRequiredApprovalScopes() {
        UserApprovalAuthorityService approvalService = mock(UserApprovalAuthorityService.class);
        Principal authentication = makeAuthentication(RAW_USERNAME);
        OAuth2ClientDetails clientDetails = makeClientDetails(CLIENT_A_ID);
        Set<ApprovalAuthority> userApprovalAuthorities = makeComposeApprovalAuthorities();
        UserAutoApprovalScopeHandler handler = new UserAutoApprovalScopeHandler(approvalService);

        when(approvalService.getApprovalAuthorities(RAW_USERNAME)).thenReturn(userApprovalAuthorities);

        Set<String> results = handler.filterRequiredPermissionScopes(authentication, clientDetails, REQUEST_SCOPES);
        assertEquals(subtract(REQUEST_SCOPES, CLIENT_A_APPROVAL_AUTHORITIES), results);
    }

    @Test
    @DisplayName("모든 스코프가 자동 승인 일때")
    void filterRequiredApprovalScopeWhenAlreadyAllScopeIsAutoApproval() {
        UserApprovalAuthorityService approvalService = mock(UserApprovalAuthorityService.class);
        Principal authentication = makeAuthentication(RAW_USERNAME);
        OAuth2ClientDetails clientDetails = makeClientDetails(CLIENT_A_ID);
        Set<ApprovalAuthority> userApprovalAuthorities = makeComposeApprovalAuthorities();
        UserAutoApprovalScopeHandler handler = new UserAutoApprovalScopeHandler(approvalService);

        when(approvalService.getApprovalAuthorities(RAW_USERNAME)).thenReturn(userApprovalAuthorities);

        Set<String> results = handler.filterRequiredPermissionScopes(authentication, clientDetails, ALL_APPROVAL_SCOPES);
        assertEquals(Collections.emptySet(), results);
    }

    @Test
    @DisplayName("자동 승인 스코프 저장")
    void storeAutoApprovalScope() {
        UserApprovalAuthorityService approvalService = mock(UserApprovalAuthorityService.class);
        Principal authentication = makeAuthentication(RAW_USERNAME);
        OAuth2ClientDetails clientDetails = makeClientDetails(CLIENT_A_ID);
        UserAutoApprovalScopeHandler handler = new UserAutoApprovalScopeHandler(approvalService);

        handler.storeAutoApprovalScopes(authentication, clientDetails, CLIENT_A_APPROVAL_AUTHORITIES);
        verify(approvalService, times(1)).grantApprovalAuthorities(RAW_USERNAME, AUTHORITIES_A);
    }

    private Set<String> subtract(Set<String> a, Set<String> b) {
        Set<String> newA = new HashSet<>(a);

        newA.removeAll(b);
        return newA;
    }

}
