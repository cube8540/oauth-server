package cube8540.oauth.authentication.oauth.scope.application;

import cube8540.oauth.authentication.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.oauth.scope.domain.OAuth2ScopeRepository;
import cube8540.oauth.authentication.oauth.scope.domain.ScopeNotFoundException;
import cube8540.oauth.authentication.oauth.scope.domain.ScopeRegisterException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static cube8540.oauth.authentication.oauth.scope.application.ScopeApplicationTestHelper.DESCRIPTION;
import static cube8540.oauth.authentication.oauth.scope.application.ScopeApplicationTestHelper.NEW_DESCRIPTION;
import static cube8540.oauth.authentication.oauth.scope.application.ScopeApplicationTestHelper.RAW_SCOPE_ID;
import static cube8540.oauth.authentication.oauth.scope.application.ScopeApplicationTestHelper.SCOPE_ID;
import static cube8540.oauth.authentication.oauth.scope.application.ScopeApplicationTestHelper.makeEmptyScopeRepository;
import static cube8540.oauth.authentication.oauth.scope.application.ScopeApplicationTestHelper.makeScope;
import static cube8540.oauth.authentication.oauth.scope.application.ScopeApplicationTestHelper.makeScopeRepository;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 스코프 디테일 서비스 테스트")
class DefaultScopeDetailsServiceTest {

    @Test
    @DisplayName("이미 저장소에 등록된 스코프 영속화")
    void persistScopeToAlreadyRegisteredInRepository() {
        OAuth2Scope scope = makeScope();
        OAuth2ScopeRepository repository = makeScopeRepository(SCOPE_ID, scope);
        OAuth2ScopeRegisterRequest request = new OAuth2ScopeRegisterRequest(RAW_SCOPE_ID, DESCRIPTION);
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);

        ScopeRegisterException e = assertThrows(ScopeRegisterException.class, () -> service.registerNewScope(request));
        assertEquals(ErrorCodes.EXISTS_IDENTIFIER, e.getCode());
    }

    @Test
    @DisplayName("새 스코프 등록")
    void registerNewScope() {
        OAuth2ScopeRepository repository = makeEmptyScopeRepository();
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);
        OAuth2ScopeRegisterRequest request = new OAuth2ScopeRegisterRequest(RAW_SCOPE_ID, DESCRIPTION);
        ArgumentCaptor<OAuth2Scope> scopeCaptor = ArgumentCaptor.forClass(OAuth2Scope.class);

        service.registerNewScope(request);
        verify(repository, times(1)).save(scopeCaptor.capture());
        assertEquals(SCOPE_ID, scopeCaptor.getValue().getCode());
        assertEquals(ScopeApplicationTestHelper.DESCRIPTION, scopeCaptor.getValue().getDescription());
    }

    @Test
    @DisplayName("저장소에 등록 되지 않은 스코프 수정")
    void modifyNotRegisteredScopeInRepository () {
        OAuth2ScopeModifyRequest request = new OAuth2ScopeModifyRequest(NEW_DESCRIPTION);
        OAuth2ScopeRepository repository = makeEmptyScopeRepository();

        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);
        assertThrows(ScopeNotFoundException.class, () -> service.modifyScope(RAW_SCOPE_ID, request));
    }

    @Test
    @DisplayName("스코프 수정")
    void modifyScope() {
        OAuth2Scope scope = makeScope();
        OAuth2ScopeRepository repository = makeScopeRepository(SCOPE_ID, scope);
        OAuth2ScopeModifyRequest request = new OAuth2ScopeModifyRequest(NEW_DESCRIPTION);
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);

        service.modifyScope(RAW_SCOPE_ID, request);
        InOrder inOrder = inOrder(scope, repository);
        inOrder.verify(scope, times(1)).setDescription(NEW_DESCRIPTION);
        inOrder.verify(repository, times(1)).save(scope);
    }

    @Test
    @DisplayName("저장소에 저장 되지 않은 스코프 삭제")
    void removeNotRegisteredScopeInRepository () {
        OAuth2ScopeRepository repository = makeEmptyScopeRepository();
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);

        assertThrows(ScopeNotFoundException.class, () -> service.removeScope(ScopeApplicationTestHelper.RAW_SCOPE_ID));
    }

    @Test
    @DisplayName("스코프 삭제")
    void removeScope () {
        OAuth2Scope scope = makeScope();
        OAuth2ScopeRepository repository = makeScopeRepository(SCOPE_ID, scope);
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);

        service.removeScope(RAW_SCOPE_ID);
        verify(repository, times(1)).delete(scope);
    }
}