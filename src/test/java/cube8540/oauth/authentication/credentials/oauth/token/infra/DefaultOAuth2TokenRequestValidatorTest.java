package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.DefaultOAuth2TokenRequestValidator;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
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

class DefaultOAuth2TokenRequestValidatorTest {

    private static final Set<String> SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    private static final Set<String> VALID_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2"));
    private static final Set<String> INVALID_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3", "SCOPE-4"));

    private OAuth2ClientDetails clientDetails;
    private DefaultOAuth2TokenRequestValidator validator = new DefaultOAuth2TokenRequestValidator();

    @BeforeEach
    void setup() {
        this.clientDetails = mock(OAuth2ClientDetails.class);
    }

    @Nested
    @DisplayName("스코프 유효성 검사")
    class ScopeValidation {

        @Nested
        @DisplayName("클라이언트가 가지고 있지 않은 스코프를 포함한 요청일시")
        class WhenIncludingScopesClientDoesNotHave {

            @BeforeEach
            void setup() {
                when(clientDetails.scope()).thenReturn(SCOPES);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환되어야 한다.")
            void shouldValidationReturnsFalse() {
                boolean result = validator.validateScopes(clientDetails, INVALID_SCOPES);

                assertFalse(result);
            }
        }

        @Nested
        @DisplayName("클라이언트가 가지고 있는 스코프만 포함한 요청일시")
        class WhenIncludingScopesClientHas {

            @BeforeEach
            void setup() {
                when(clientDetails.scope()).thenReturn(SCOPES);
            }

            @Test
            @DisplayName("유효성 검사시 true가 반환되어야 한다.")
            void shouldValidationReturnsTrue() {
                boolean result = validator.validateScopes(clientDetails, VALID_SCOPES);

                assertTrue(result);
            }
        }

        @Nested
        @DisplayName("요청 스코프가 비어있거나 null일시")
        class WhenRequestScopeNullOrEmpty {

            @Nested
            @DisplayName("스코프가 비어있을시")
            class WhenScopeEmpty {

                @BeforeEach
                void setup() {
                    when(clientDetails.scope()).thenReturn(SCOPES);
                }

                @Test
                @DisplayName("유효성 검사시 true가 반환되어야 한다.")
                void shouldValidationReturnsTrue() {
                    boolean result = validator.validateScopes(clientDetails, Collections.emptySet());

                    assertTrue(result);
                }
            }

            @Nested
            @DisplayName("스코프가 null일시")
            class WhenScopeNull {

                @BeforeEach
                void setup() {
                    when(clientDetails.scope()).thenReturn(SCOPES);
                }

                @Test
                @DisplayName("유효성 검사시 true가 반환되어야 한다.")
                void shouldValidationReturnsTrue() {
                    boolean result = validator.validateScopes(clientDetails, null);

                    assertTrue(result);
                }
            }
        }
    }
}