package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.security.DefaultOAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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

    @Nested
    @DisplayName("스코프 유효성 검사")
    class ScopeValidation {

        @Nested
        @DisplayName("클라이언트가 가지고 있지 않은 스코프를 포함한 요청일시")
        class WhenIncludingScopesClientDoesNotHave {
            private Set<String> scopes;
            private OAuth2ClientDetails clientDetails;

            private DefaultOAuth2RequestValidator validator;

            @BeforeEach
            void setup() {
                this.clientDetails = mock(OAuth2ClientDetails.class);
                this.scopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3", "SCOPE-4"));
                this.validator = new DefaultOAuth2RequestValidator();

                Set<String> clientScopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
                when(clientDetails.getScopes()).thenReturn(clientScopes);
            }

            @Test
            @DisplayName("유효성 검사시 false 가 반환되어야 한다.")
            void shouldValidationReturnsFalse() {
                boolean result = validator.validateScopes(clientDetails, scopes);

                assertFalse(result);
            }
        }

        @Nested
        @DisplayName("클라이언트가 가지고 있는 스코프만 포함한 요청일시")
        class WhenIncludingScopesClientHas {
            private Set<String> scopes;
            private OAuth2ClientDetails clientDetails;

            private DefaultOAuth2RequestValidator validator;

            @BeforeEach
            void setup() {
                this.clientDetails = mock(OAuth2ClientDetails.class);
                this.scopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
                this.validator = new DefaultOAuth2RequestValidator();

                Set<String> clientScopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3", "SCOPE-4"));
                when(clientDetails.getScopes()).thenReturn(clientScopes);
            }

            @Test
            @DisplayName("유효성 검사시 true 가 반환되어야 한다.")
            void shouldValidationReturnsTrue() {
                boolean result = validator.validateScopes(clientDetails, scopes);

                assertTrue(result);
            }
        }

        @Nested
        @DisplayName("요청 스코프가 비어있거나 null일시")
        class WhenRequestScopeNullOrEmpty {

            @Nested
            @DisplayName("스코프가 비어있을시")
            class WhenScopeEmpty {
                private OAuth2ClientDetails clientDetails;

                private DefaultOAuth2RequestValidator validator;

                @BeforeEach
                void setup() {
                    this.clientDetails = mock(OAuth2ClientDetails.class);
                    this.validator = new DefaultOAuth2RequestValidator();

                    Set<String> clientScopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3", "SCOPE-4"));
                    when(clientDetails.getScopes()).thenReturn(clientScopes);
                }

                @Test
                @DisplayName("유효성 검사시 true 가 반환되어야 한다.")
                void shouldValidationReturnsTrue() {
                    boolean result = validator.validateScopes(clientDetails, Collections.emptySet());

                    assertTrue(result);
                }
            }

            @Nested
            @DisplayName("스코프가 null일시")
            class WhenScopeNull {
                private OAuth2ClientDetails clientDetails;

                private DefaultOAuth2RequestValidator validator;

                @BeforeEach
                void setup() {
                    this.clientDetails = mock(OAuth2ClientDetails.class);
                    this.validator = new DefaultOAuth2RequestValidator();

                    Set<String> clientScopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3", "SCOPE-4"));
                    when(clientDetails.getScopes()).thenReturn(clientScopes);
                }

                @Test
                @DisplayName("유효성 검사시 true 가 반환되어야 한다.")
                void shouldValidationReturnsTrue() {
                    boolean result = validator.validateScopes(clientDetails, null);

                    assertTrue(result);
                }
            }
        }
    }
}