package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeInvalidException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.DESCRIPTION;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.RAW_SCOPE_ID;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.makeErrorValidatorFactory;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.makePassValidatorFactory;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
}