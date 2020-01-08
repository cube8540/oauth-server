package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.mock;

@DisplayName("OAuth2 인증 코드 도메인 테스트")
class OAuth2AuthorizationCodeTest {

    private static final String RAW_CODE = "CODE";
    private static final AuthorizationCode CODE = new AuthorizationCode(RAW_CODE);

    private static final LocalDateTime EXPIRED_DATETIME = LocalDateTime.now().minusNanos(1);
    private static final LocalDateTime NOT_EXPIRED_DATETIME = LocalDateTime.now().plusMinutes(1);

    private static final List<OAuth2ScopeId> SCOPES = Arrays.asList(
            new OAuth2ScopeId("SCOPE-1"),
            new OAuth2ScopeId("SCOPE-2"),
            new OAuth2ScopeId("SCOPE-3"));

    private AuthorizationCodeGenerator generator;

    @BeforeEach
    void setup() {
        this.generator = mock(AuthorizationCodeGenerator.class);
    }

}