package cube8540.oauth.authentication.users.infra;

import cube8540.oauth.authentication.oauth.error.OAuth2ClientRegistrationException;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.users.domain.ApprovalAuthority;
import cube8540.oauth.authentication.users.domain.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 승인 권한 검사 테스트")
public class DefaultApprovalAuthorityValidationRuleTest {

    private static final String CLIENT_ID = "CLIENT-ID";
    private static final String NOT_FOUND_CLIENT_ID = "NOT-FOUND-CLIENT-ID";
    private static final Set<String> CLIENT_SCOPES = new HashSet<>(Arrays.asList("TEST-1", "TEST-2", "TEST-3"));

    private static final Set<String> ALLOW_REQUEST_SCOPES = new HashSet<>(Arrays.asList("TEST-1", "TEST-2"));
    private static final Set<String> INCLUDE_NOT_SCOPE_FOR_CLIENT = new HashSet<>(Arrays.asList("TEST-1", "TEST-2", "TEST-4"));

    private OAuth2ClientDetailsService clientDetailsService;
    private DefaultApprovalAuthorityValidationRule rule;

    @BeforeEach
    void setup() {
        this.clientDetailsService = mock(OAuth2ClientDetailsService.class);

        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
        when(clientDetails.getClientId()).thenReturn(CLIENT_ID);
        when(clientDetails.getScopes()).thenReturn(CLIENT_SCOPES);

        when(clientDetailsService.loadClientDetailsByClientId(CLIENT_ID)).thenReturn(clientDetails);
        when(clientDetailsService.loadClientDetailsByClientId(NOT_FOUND_CLIENT_ID)).thenThrow(new OAuth2ClientRegistrationException("NOT FOUND"));
        this.rule = new DefaultApprovalAuthorityValidationRule();
    }

    @Test
    @DisplayName("클라이언트 검색 서비스가 없을시")
    void clientDetailsServiceIsNull() {
        assertFalse(rule.isValid(mock(User.class)));
    }

    @Test
    @DisplayName("승인 권한이 null 일때")
    void approvalAuthorityIsNull() {
        User user = mock(User.class);

        this.rule.setClientDetailsService(this.clientDetailsService);
        when(user.getApprovalAuthorities()).thenReturn(null);

        assertTrue(rule.isValid(user));
    }

    @Test
    @DisplayName("승인 권한이 비어 있을때")
    void approvalAuthorityIsEmpty() {
        User user = mock(User.class);

        this.rule.setClientDetailsService(this.clientDetailsService);
        when(user.getApprovalAuthorities()).thenReturn(Collections.emptySet());

        assertTrue(rule.isValid(user));
    }

    @Test
    @DisplayName("클라이언트가 검색 되지 않을때")
    void clientIsNotFound() {
        User user = mock(User.class);

        this.rule.setClientDetailsService(this.clientDetailsService);
        when(user.getApprovalAuthorities()).thenReturn(makeAuthority(NOT_FOUND_CLIENT_ID, ALLOW_REQUEST_SCOPES));

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("클라이언트의 스코프 외의 다른 것을 포함 하고 있을시")
    void includeNotScopeForClient() {
        User user = mock(User.class);

        this.rule.setClientDetailsService(this.clientDetailsService);
        when(user.getApprovalAuthorities()).thenReturn(makeAuthority(CLIENT_ID, INCLUDE_NOT_SCOPE_FOR_CLIENT));

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("요청 스코프를 모두 클라이언트가 가지고 있을시")
    void clientHasAllOfTheRequestedScopes() {
        User user = mock(User.class);

        this.rule.setClientDetailsService(this.clientDetailsService);
        when(user.getApprovalAuthorities()).thenReturn(makeAuthority(CLIENT_ID, ALLOW_REQUEST_SCOPES));

        assertTrue(rule.isValid(user));
    }

    @AfterEach
    void cleanUp() {
        this.rule = null;
    }

    private Set<ApprovalAuthority> makeAuthority(String clientId, Set<String> authorities) {
        return authorities.stream()
                .map(authority -> new ApprovalAuthority(clientId, authority))
                .collect(Collectors.toSet());
    }

}
