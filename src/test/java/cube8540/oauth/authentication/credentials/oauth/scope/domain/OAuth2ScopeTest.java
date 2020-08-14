package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeInvalidException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.ACCESSIBLE_AUTHORITY;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.AUTHORITY_CODE;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.DESCRIPTION;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.GRANTED_AUTHORITIES;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.NOT_ACCESSIBLE_AUTHORITIES;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.RAW_SCOPE_ID;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.makeAuthentication;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.makeErrorValidatorFactory;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.makePassValidatorFactory;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OAuth2 스코프 테스트")
class OAuth2ScopeTest {

    @Test
    @DisplayName("유효 하지 않은 정보가 저장 되어 있을시")
    void scopeDataInvalid() {
        OAuth2Scope scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);

        OAuth2ScopeValidatorFactory factory = makeErrorValidatorFactory(scope);

        assertThrows(ScopeInvalidException.class, () -> scope.validate(factory));
    }

    @Test
    @DisplayName("모든 데이터가 유효할시")
    void scopeDataAllowed() {
        OAuth2Scope scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);

        OAuth2ScopeValidatorFactory factory = makePassValidatorFactory(scope);

        assertDoesNotThrow(() -> scope.validate(factory));
    }

    @Test
    @DisplayName("접근 가능한 권한 추가")
    void addAccessibleAuthority() {
        OAuth2Scope scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);

        scope.addAccessibleAuthority(AUTHORITY_CODE);
        assertTrue(scope.getAccessibleAuthority().contains(AUTHORITY_CODE));
    }

    @Test
    @DisplayName("접근 권한 제거")
    void removeAccessibleAuthority() {
        OAuth2Scope scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);

        scope.addAccessibleAuthority(AUTHORITY_CODE);

        scope.removeAccessibleAuthority(AUTHORITY_CODE);
        assertFalse(scope.getAccessibleAuthority().contains(AUTHORITY_CODE));
    }

    @Test
    @DisplayName("스코프의 접근 가능한 권한이 null 일시")
    void whenAccessibleAuthorityIsNullTestAccess() {
        OAuth2Scope scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
        Authentication authentication = makeAuthentication(GRANTED_AUTHORITIES);

        assertFalse(scope.isAccessible(authentication));
    }

    @Test
    @DisplayName("인증 정보에 접근 가능한 권한이 없을시")
    void whenAuthenticationHasNotAuthority() {
        OAuth2Scope scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
        Authentication authentication = makeAuthentication(NOT_ACCESSIBLE_AUTHORITIES);

        ACCESSIBLE_AUTHORITY.forEach(scope::addAccessibleAuthority);

        assertFalse(scope.isAccessible(authentication));
    }

    @Test
    @DisplayName("인증 정보에 접근 가능항 권한이 있을시")
    void whenAuthenticationHasAccessibleAuthority() {
        OAuth2Scope scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
        Authentication authentication = makeAuthentication(GRANTED_AUTHORITIES);

        ACCESSIBLE_AUTHORITY.forEach(scope::addAccessibleAuthority);

        assertTrue(scope.isAccessible(authentication));
    }
}