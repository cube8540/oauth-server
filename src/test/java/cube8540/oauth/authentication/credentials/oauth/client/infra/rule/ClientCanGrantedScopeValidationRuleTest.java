package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2ScopeManagementService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트의 스코프가 null 일때 유효성 검사")
    void validationWhenClientScopeIsNull() {
        OAuth2Client client = mock(OAuth2Client.class);
        OAuth2ScopeManagementService service = mock(OAuth2ScopeManagementService.class);
        ClientCanGrantedScopeValidationRule rule = new ClientCanGrantedScopeValidationRule();

        when(client.getScopes()).thenReturn(null);
        rule.setScopeDetailsService(service);

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트의 스코프가 비어 있을시 유효성 검사")
    void validationWhenClientScopeIsEmpty() {
        OAuth2Client client = mock(OAuth2Client.class);
        OAuth2ScopeManagementService service = mock(OAuth2ScopeManagementService.class);
        ClientCanGrantedScopeValidationRule rule = new ClientCanGrantedScopeValidationRule();

        when(client.getScopes()).thenReturn(Collections.emptySet());
        rule.setScopeDetailsService(service);

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트의 스코프 중 검색 되지 않는 스코프가 있을시")
    void clientScopeCannotBeFound() {
        OAuth2Client client = mock(OAuth2Client.class);
        OAuth2ScopeManagementService service = mock(OAuth2ScopeManagementService.class);
        List<AuthorityDetails> scopes = Arrays.asList(makeScope("SCOPE-1"), makeScope("SCOPE-2"), makeScope("SCOPE-3"));
        Set<AuthorityCode> clientScopes = new HashSet<>(Arrays.asList(new AuthorityCode("SCOPE-1"), new AuthorityCode("SCOPE-2"), new AuthorityCode("SCOPE-6")));

        when(client.getScopes()).thenReturn(clientScopes);
        when(service.loadScopes()).thenReturn(scopes);
        rule.setScopeDetailsService(service);

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트의 스코프가 모두 검색 되는 스코프일시")
    void clientScopeCanBeFound() {
        OAuth2Client client = mock(OAuth2Client.class);
        OAuth2ScopeManagementService service = mock(OAuth2ScopeManagementService.class);
        List<AuthorityDetails> scopes = Arrays.asList(makeScope("SCOPE-1"), makeScope("SCOPE-2"), makeScope("SCOPE-3"));
        Set<AuthorityCode> clientScopes = new HashSet<>(Arrays.asList(new AuthorityCode("SCOPE-1"), new AuthorityCode("SCOPE-2"), new AuthorityCode("SCOPE-3")));

        when(client.getScopes()).thenReturn(clientScopes);
        when(service.loadScopes()).thenReturn(scopes);
        rule.setScopeDetailsService(service);

        assertTrue(rule.isValid(client));
    }

    private AuthorityDetails makeScope(String scopeId) {
        AuthorityDetails scopeDetails = mock(AuthorityDetails.class);

        when(scopeDetails.getCode()).thenReturn(scopeId);
        return scopeDetails;
    }

}