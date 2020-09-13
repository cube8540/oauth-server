package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidatorFactory;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeRegisterException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.DESCRIPTION;
import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.MODIFY_SECURED;
import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.NEW_DESCRIPTION;
import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.RAW_SCOPE_ID;
import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.SCOPE_ID;
import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.SECURED;
import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.makeEmptyScopeRepository;
import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.makeErrorValidatorFactory;
import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.makeScope;
import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.makeScopeRepository;
import static cube8540.oauth.authentication.credentials.oauth.scope.application.ScopeApplicationTestHelper.makeValidatorFactory;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 스코프 디테일 서비스 테스트")
class DefaultScopeDetailsServiceTest {

    @Test
    @DisplayName("이미 저장소에 등록된 스코프 영속화")
    void persistScopeToAlreadyRegisteredInRepository() {
        OAuth2Scope scope = makeScope();
        OAuth2ScopeRepository repository = makeScopeRepository(SCOPE_ID, scope);
        OAuth2ScopeRegisterRequest request = new OAuth2ScopeRegisterRequest(RAW_SCOPE_ID, DESCRIPTION, SECURED);
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);

        ScopeRegisterException e = assertThrows(ScopeRegisterException.class, () -> service.registerNewScope(request));
        assertEquals(ErrorCodes.EXISTS_IDENTIFIER, e.getCode());
    }

    @Test
    @DisplayName("유효 하지 않은 데이터로 스코프 등록시")
    void registerScopeWithInvalidData() {
        OAuth2ScopeRepository repository = makeEmptyScopeRepository();
        OAuth2ScopeValidatorFactory factory = makeErrorValidatorFactory(new TestScopeException());
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);
        OAuth2ScopeRegisterRequest request = new OAuth2ScopeRegisterRequest(RAW_SCOPE_ID, DESCRIPTION, null);

        service.setValidatorFactory(factory);

        assertThrows(TestScopeException.class, () -> service.registerNewScope(request));
    }

    @Test
    @DisplayName("보호 여부 없이 스코프를 등록시")
    void registerNewScopeWithoutSecured() {
        OAuth2ScopeRepository repository = makeEmptyScopeRepository();
        OAuth2ScopeValidatorFactory factory = makeValidatorFactory();
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);
        OAuth2ScopeRegisterRequest request = new OAuth2ScopeRegisterRequest(RAW_SCOPE_ID, DESCRIPTION, null);
        ArgumentCaptor<OAuth2Scope> scopeCaptor = ArgumentCaptor.forClass(OAuth2Scope.class);

        service.setValidatorFactory(factory);

        service.registerNewScope(request);
        verify(repository, times(1)).save(scopeCaptor.capture());
        assertEquals(SCOPE_ID, scopeCaptor.getValue().getCode());
        assertEquals(ScopeApplicationTestHelper.DESCRIPTION, scopeCaptor.getValue().getDescription());
        assertTrue(scopeCaptor.getValue().isSecured());
    }

    @Test
    @DisplayName("새 스코프 등록")
    void registerNewScope() {
        OAuth2ScopeRepository repository = makeEmptyScopeRepository();
        OAuth2ScopeValidatorFactory factory = makeValidatorFactory();
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);
        OAuth2ScopeRegisterRequest request = new OAuth2ScopeRegisterRequest(RAW_SCOPE_ID, DESCRIPTION, SECURED);
        ArgumentCaptor<OAuth2Scope> scopeCaptor = ArgumentCaptor.forClass(OAuth2Scope.class);

        service.setValidatorFactory(factory);

        service.registerNewScope(request);
        verify(repository, times(1)).save(scopeCaptor.capture());
        assertEquals(SCOPE_ID, scopeCaptor.getValue().getCode());
        assertEquals(ScopeApplicationTestHelper.DESCRIPTION, scopeCaptor.getValue().getDescription());
        assertEquals(SECURED, scopeCaptor.getValue().isSecured());
    }

    @Test
    @DisplayName("저장소에 등록 되지 않은 스코프 수정")
    void modifyNotRegisteredScopeInRepository () {
        OAuth2ScopeModifyRequest request = new OAuth2ScopeModifyRequest(NEW_DESCRIPTION, SECURED);
        OAuth2ScopeRepository repository = makeEmptyScopeRepository();

        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);
        assertThrows(ScopeNotFoundException.class, () -> service.modifyScope(RAW_SCOPE_ID, request));
    }

    @Test
    @DisplayName("삭제할 접근 권한 없이 스코프를 수정")
    void modifyScopeWithOutRemoveAuthorities () {
        OAuth2Scope scope = makeScope();
        OAuth2ScopeRepository repository = makeScopeRepository(SCOPE_ID, scope);
        OAuth2ScopeModifyRequest request = new OAuth2ScopeModifyRequest(NEW_DESCRIPTION, SECURED);
        OAuth2ScopeValidatorFactory factory = makeValidatorFactory();
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);

        service.setValidatorFactory(factory);

        service.modifyScope(RAW_SCOPE_ID, request);
        InOrder inOrder = inOrder(scope, repository);
        inOrder.verify(scope, times(1)).setDescription(NEW_DESCRIPTION);
        inOrder.verify(scope, times(1)).validate(factory);
        inOrder.verify(repository, times(1)).save(scope);
    }

    @Test
    @DisplayName("자원 보호 여부 없이 스코프 수정")
    void modifyScopeWithoutSecured() {
        OAuth2Scope scope = makeScope();
        OAuth2ScopeRepository repository = makeScopeRepository(SCOPE_ID, scope);
        OAuth2ScopeModifyRequest request = new OAuth2ScopeModifyRequest(NEW_DESCRIPTION, null);
        OAuth2ScopeValidatorFactory factory = makeValidatorFactory();
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);

        service.setValidatorFactory(factory);

        service.modifyScope(RAW_SCOPE_ID, request);
        InOrder inOrder = inOrder(scope, repository);
        inOrder.verify(scope, times(1)).setDescription(NEW_DESCRIPTION);
        inOrder.verify(scope, never()).setSecured(any());
        inOrder.verify(scope, times(1)).validate(factory);
        inOrder.verify(repository, times(1)).save(scope);
    }

    @Test
    @DisplayName("스코프 수정")
    void modifyScope() {
        OAuth2Scope scope = makeScope();
        OAuth2ScopeRepository repository = makeScopeRepository(SCOPE_ID, scope);
        OAuth2ScopeModifyRequest request = new OAuth2ScopeModifyRequest(NEW_DESCRIPTION, MODIFY_SECURED);
        OAuth2ScopeValidatorFactory factory = makeValidatorFactory();
        DefaultScopeDetailsService service = new DefaultScopeDetailsService(repository);

        service.setValidatorFactory(factory);

        service.modifyScope(RAW_SCOPE_ID, request);
        InOrder inOrder = inOrder(scope, repository);
        inOrder.verify(scope, times(1)).setDescription(NEW_DESCRIPTION);
        inOrder.verify(scope, times(1)).setSecured(MODIFY_SECURED);
        inOrder.verify(scope, times(1)).validate(factory);
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

    private static class TestScopeException extends RuntimeException {}
}