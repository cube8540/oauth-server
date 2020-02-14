package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

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

    @Nested
    @DisplayName("접근 가능한 권한 추가")
    class AddAccessibleAuthority {
        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
        }

        @Nested
        @DisplayName("새 접근 가능한 권한을 추가했을시")
        class WhenAddedNewAccessibleAuthority {
            private AuthorityCode code;

            @BeforeEach
            void setup() {
                this.code = new AuthorityCode("AUTHORITY-CODE");
            }

            @Test
            @DisplayName("인자로 받은 권한을 저장해야 한다.")
            void shouldSaveGivenAuthority() {
                scope.addAccessibleAuthority(code);

                assertTrue(scope.getAccessibleAuthority().contains(code));
            }
        }

        @Nested
        @DisplayName("이미 저장되어 있는 권한을 추가할시")
        class WhenAddedExistsAuthority {
            private AuthorityCode code;

            @BeforeEach
            void setup() {
                this.code = new AuthorityCode("AUTHORITY-CODE");
                scope.addAccessibleAuthority(code);
            }

            @Test
            @DisplayName("같은 권한은 하나만 저장되어 있어야 한다.")
            void shouldStoredOnlyOneSameAuthority() {
                scope.addAccessibleAuthority(code);

                long count = scope.getAccessibleAuthority().stream().filter(code -> code.equals(this.code)).count();
                assertEquals(1, count);
            }
        }
    }

    @Nested
    @DisplayName("접근 권한 제거")
    class RemoveAccessibleAuthority {

        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
        }

        @Nested
        @DisplayName("저장되지 않은 권한을 삭제할시")
        class WhenRemovedNotStoredAuthority {
            private AuthorityCode code;

            @BeforeEach
            void setup() {
                this.code = new AuthorityCode("AUTHORITY-CODE");
            }

            @Test
            @DisplayName("해당 요청은 무시한다.")
            void shouldIgnoreRequesting() {
                assertDoesNotThrow(() -> scope.removeAccessibleAuthority(code));
            }
        }

        @Nested
        @DisplayName("저장되어 있는 권한을 삭제시")
        class WhenRemovedStoredAuthority {
            private AuthorityCode code;

            @BeforeEach
            void setup() {
                this.code = new AuthorityCode("AUTHORITY-CODE");
                scope.addAccessibleAuthority(code);
            }

            @Test
            @DisplayName("인자로 받은 권한을 삭제한다.")
            void shouldRemovedRequestingAuthority() {
                scope.removeAccessibleAuthority(code);

                assertFalse(scope.getAccessibleAuthority().contains(code));
            }
        }
    }

    @Nested
    @DisplayName("접근 가능 확인")
    class TestAccessible {
        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
        }

        @Nested
        @DisplayName("스코프의 접근 가능한 권한이 null일시")
        class WhenScopeAccessibleAuthorityIsNull {
            private Authentication authentication;

            @BeforeEach
            void setup() {
                this.authentication = mock(Authentication.class);

                Collection<? extends GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("SCOPE-1"),
                        new SimpleGrantedAuthority("SCOPE-2"),
                        new SimpleGrantedAuthority("SCOPE-3"));
                doReturn(authorities).when(authentication).getAuthorities();
            }

            @Test
            @DisplayName("접근 가능 여부는 false가 반환되어야 한다.")
            void shouldReturnsFalse() {
                assertFalse(scope.isAccessible(authentication));
            }
        }

        @Nested
        @DisplayName("스코프의 접근 가능한 권한이 null이 아닐시")
        class WhenScopeAccessibleAuthorityIsNotNull {

            @BeforeEach
            void setup() {
                scope.addAccessibleAuthority(new AuthorityCode("AUTHORITY-CODE-1"));
                scope.addAccessibleAuthority(new AuthorityCode("AUTHORITY-CODE-2"));
                scope.addAccessibleAuthority(new AuthorityCode("AUTHORITY-CODE-3"));
            }

            @Nested
            @DisplayName("인증 정보에 접근 가능한 권한이 없을시")
            class WhenAuthenticationNotHaveAccessibleAuthority {
                private Authentication authentication;

                @BeforeEach
                void setup() {
                    this.authentication = mock(Authentication.class);

                    Collection<? extends GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("SCOPE-1"),
                            new SimpleGrantedAuthority("SCOPE-2"),
                            new SimpleGrantedAuthority("SCOPE-3"));
                    doReturn(authorities).when(authentication).getAuthorities();
                }

                @Test
                @DisplayName("접근 가능 여부는 false가 반환되어야 한다.")
                void shouldReturnsFalse() {
                    assertFalse(scope.isAccessible(authentication));
                }
            }

            @Nested
            @DisplayName("인증 정보에 접근 가능한 권한이 있을시")
            class WhenAuthenticationHaveAccessibleAuthority {
                private Authentication authentication;

                @BeforeEach
                void setup() {
                    this.authentication = mock(Authentication.class);

                    Collection<? extends GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("AUTHORITY-CODE-1"),
                            new SimpleGrantedAuthority("SCOPE-2"),
                            new SimpleGrantedAuthority("SCOPE-3"));
                    doReturn(authorities).when(authentication).getAuthorities();
                }

                @Test
                @DisplayName("접근 가능 여부는 true가 반환되어야 한다.")
                void shouldReturnsTrue() {
                    assertTrue(scope.isAccessible(authentication));
                }
            }
        }
    }
}