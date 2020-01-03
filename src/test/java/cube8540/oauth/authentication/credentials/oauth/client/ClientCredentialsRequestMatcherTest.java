package cube8540.oauth.authentication.credentials.oauth.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 인증 요청 URI 매칭 테스트")
class ClientCredentialsRequestMatcherTest {

    private static final String CONTEXT_PATH = "http://localhost:8080";
    private static final String PATH = "/oauth2/token";

    private ClientCredentialsRequestMatcher matcher;

    @BeforeEach
    void setup() {
        this.matcher = new ClientCredentialsRequestMatcher(PATH);
    }

    @Nested
    @DisplayName("URI 매칭")
    class WhenMatchesURI {

        @Nested
        @DisplayName("URI가 매칭되지 않을시")
        class WhenUriNotMatched {

            private HttpServletRequest request;

            @BeforeEach
            void setup() {
                this.request = mock(HttpServletRequest.class);
                when(this.request.getContextPath()).thenReturn(CONTEXT_PATH);
                when(this.request.getRequestURI()).thenReturn("/NOT_MATCHED_PATH");
            }

            @Test
            @DisplayName("매칭 결과는 false가 반환되어야 한다.")
            void shouldReturnsFalse() {
                boolean matches = matcher.matches(request);
                assertFalse(matches);
            }
        }

        @Nested
        @DisplayName("URI가 매칭 될시")
        class WhenUriMatched {

            @Nested
            @DisplayName("Context Path가 null일시")
            class WhenContextPathNull {

                private HttpServletRequest request;

                @BeforeEach
                void setup() {
                    this.request = mock(HttpServletRequest.class);
                    when(this.request.getRequestURI()).thenReturn(PATH);
                }

                @Test
                @DisplayName("매칭 결과는 true가 반환되어야 한다.")
                void shouldReturnTrue() {
                    boolean matches = matcher.matches(request);
                    assertTrue(matches);
                }
            }

            @Nested
            @DisplayName("Context Path가 공백일시")
            class WhenEmptyContextPath {

                private HttpServletRequest request;

                @BeforeEach
                void setup() {
                    this.request = mock(HttpServletRequest.class);
                    when(request.getContextPath()).thenReturn("");
                    when(request.getRequestURI()).thenReturn("" + PATH);
                }

                @Test
                @DisplayName("매칭 결과는 true가 반환되어야 한다.")
                void shouldReturnTrue() {
                    boolean matches = matcher.matches(request);
                    assertTrue(matches);
                }
            }

            @Nested
            @DisplayName("Context Path가 빈값이 아닐시")
            class WhenNotEmptyContextPath {

                private HttpServletRequest request;

                @BeforeEach
                void setup() {
                    this.request = mock(HttpServletRequest.class);
                    when(request.getContextPath()).thenReturn(CONTEXT_PATH);
                    when(request.getRequestURI()).thenReturn(CONTEXT_PATH + PATH);
                }

                @Test
                @DisplayName("매칭 결과는 true가 반환되어야 한다.")
                void shouldReturnTrue() {
                    boolean matches = matcher.matches(request);
                    assertTrue(matches);
                }
            }
        }
    }

}