package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.security.DefaultOAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 OAuth2 요청 유효성 검사 유틸 클래스 테스트")
class DefaultOAuth2RequestValidatorTest {

    @Test
    @DisplayName("클라이언트가 가지고 있지 않은 스코프를 포함한 요청 일때")
    void whenRequestIncludesScopeClientDoesNotHave() {
        Set<String> scopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3", "SCOPE-4"));
        Set<String> clientScopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
        DefaultOAuth2RequestValidator validator = new DefaultOAuth2RequestValidator();

        when(clientDetails.getScopes()).thenReturn(clientScopes);

        assertFalse(validator.validateScopes(clientDetails, scopes));
    }

    @Test
    @DisplayName("클라이언트가 가지고 있는 스코프를 포함한 요청 일때")
    void whenRequestIncludesScopeClientHas() {
        Set<String> scopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
        Set<String> clientScopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3", "SCOPE-4"));
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
        DefaultOAuth2RequestValidator validator = new DefaultOAuth2RequestValidator();

        when(clientDetails.getScopes()).thenReturn(clientScopes);

        assertTrue(validator.validateScopes(clientDetails, scopes));
    }

    @Test
    @DisplayName("요청 스코프가 null 일때")
    void whenRequestScopesIsNull() {
        Set<String> clientScopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3", "SCOPE-4"));
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
        DefaultOAuth2RequestValidator validator = new DefaultOAuth2RequestValidator();

        when(clientDetails.getScopes()).thenReturn(clientScopes);

        assertTrue(validator.validateScopes(clientDetails, null));
    }

    @Test
    @DisplayName("요청 스코프가 비어 있을때")
    void whenRequestScopesIsEmpty() {
        Set<String> clientScopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3", "SCOPE-4"));
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
        DefaultOAuth2RequestValidator validator = new DefaultOAuth2RequestValidator();

        when(clientDetails.getScopes()).thenReturn(clientScopes);

        assertTrue(validator.validateScopes(clientDetails, Collections.emptySet()));
    }
}