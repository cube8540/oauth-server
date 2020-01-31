package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("OAuth2 스코프 테스트")
class OAuth2ScopeTest {

    private static final String RAW_SCOPE_ID = "OAUTH2_SCOPE";
    private static final OAuth2ScopeId SCOPE_ID = new OAuth2ScopeId(RAW_SCOPE_ID);
    private static final String DESCRIPTION = "DESCRIPTION";

    @Nested
    @DisplayName("스코프 생성")
    class InitializeScope {
        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
        }

        @Test
        @DisplayName("인자로 받은 스코프 아이디를 저장해야 한다.")
        void shouldSaveGivenScopeId() {
            assertEquals(SCOPE_ID, scope.getId());
        }

        @Test
        @DisplayName("인자로 받은 스코프 설명을 저장해야 한다.")
        void shouldSaveGivenDescription() {
            assertEquals(DESCRIPTION, scope.getDescription());
        }
    }

}