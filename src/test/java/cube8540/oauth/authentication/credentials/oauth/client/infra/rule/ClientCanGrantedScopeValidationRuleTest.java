package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2AccessibleScopeDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 스코프 부여 가능 여부를 확인 하는 클래스 테스트")
class ClientCanGrantedScopeValidationRuleTest {

    private ClientCanGrantedScopeValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new ClientCanGrantedScopeValidationRule();
    }

    @Test
    @DisplayName("스코프 검색 서비스가 null 일때 유효성 검사")
    void validationWhenScopeSearchServiceIsNull() {
        ClientCanGrantedScopeValidationRule rule = new ClientCanGrantedScopeValidationRule();

        OAuth2Client client = mock(OAuth2Client.class);
        rule.setSecurityContext(mock(SecurityContext.class));

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("인증 컨텍스트가 null 일때 유효성 검사")
    void validationWhenSecurityContextIsNull() {
        OAuth2Client client = mock(OAuth2Client.class);
        OAuth2AccessibleScopeDetailsService service = mock(OAuth2AccessibleScopeDetailsService.class);
        ClientCanGrantedScopeValidationRule rule = new ClientCanGrantedScopeValidationRule();

        rule.setScopeDetailsService(service);

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트의 스코프가 null 일때 유효성 검사")
    void validationWhenClientScopeIsNull() {
        OAuth2Client client = mock(OAuth2Client.class);
        OAuth2AccessibleScopeDetailsService service = mock(OAuth2AccessibleScopeDetailsService.class);
        SecurityContext securityContext = mock(SecurityContext.class);
        ClientCanGrantedScopeValidationRule rule = new ClientCanGrantedScopeValidationRule();

        when(client.getScopes()).thenReturn(null);
        rule.setScopeDetailsService(service);
        rule.setSecurityContext(securityContext);

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트의 스코프가 비어 있을시 유효성 검사")
    void validationWhenClientScopeIsEmpty() {
        OAuth2Client client = mock(OAuth2Client.class);
        OAuth2AccessibleScopeDetailsService service = mock(OAuth2AccessibleScopeDetailsService.class);
        SecurityContext securityContext = mock(SecurityContext.class);
        ClientCanGrantedScopeValidationRule rule = new ClientCanGrantedScopeValidationRule();

        when(client.getScopes()).thenReturn(Collections.emptySet());
        rule.setScopeDetailsService(service);
        rule.setSecurityContext(securityContext);

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트의 스코프 중 인증 받은 유저가 접근 훌 수 없는 스코프가 있을시")
    void WhenScopesOnTheClientAreInaccessibleToTheAuthenticatedUser() {
        OAuth2Client client = mock(OAuth2Client.class);
        Authentication authentication = mock(Authentication.class);
        OAuth2AccessibleScopeDetailsService service = mock(OAuth2AccessibleScopeDetailsService.class);
        SecurityContext securityContext = mock(SecurityContext.class);
        List<AuthorityDetails> scopes = Arrays.asList(makeScope("SCOPE-1"), makeScope("SCOPE-2"), makeScope("SCOPE-3"));
        Set<AuthorityCode> clientScopes = new HashSet<>(Arrays.asList(new AuthorityCode("SCOPE-1"), new AuthorityCode("SCOPE-2"), new AuthorityCode("SCOPE-6")));

        when(client.getScopes()).thenReturn(clientScopes);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(service.readAccessibleScopes(authentication)).thenReturn(scopes);
        rule.setScopeDetailsService(service);
        rule.setSecurityContext(securityContext);

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트의 스코프가 모두 인증 받은 유저가 접근 할 수 있는 스코프일시")
    void WhenScopeOnTheClientAreAccessibleToTheAuthenticatedUser() {
        OAuth2Client client = mock(OAuth2Client.class);
        Authentication authentication = mock(Authentication.class);
        OAuth2AccessibleScopeDetailsService service = mock(OAuth2AccessibleScopeDetailsService.class);
        SecurityContext securityContext = mock(SecurityContext.class);
        List<AuthorityDetails> scopes = Arrays.asList(makeScope("SCOPE-1"), makeScope("SCOPE-2"), makeScope("SCOPE-3"));
        Set<AuthorityCode> clientScopes = new HashSet<>(Arrays.asList(new AuthorityCode("SCOPE-1"), new AuthorityCode("SCOPE-2"), new AuthorityCode("SCOPE-3")));

        when(client.getScopes()).thenReturn(clientScopes);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(service.readAccessibleScopes(authentication)).thenReturn(scopes);
        rule.setScopeDetailsService(service);
        rule.setSecurityContext(securityContext);

        assertTrue(rule.isValid(client));
    }

    private AuthorityDetails makeScope(String scopeId) {
        AuthorityDetails scopeDetails = mock(AuthorityDetails.class);

        when(scopeDetails.getCode()).thenReturn(scopeId);
        return scopeDetails;
    }

}