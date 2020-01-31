package cube8540.oauth.authentication.credentials.authority.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("권한 도메인 테스트")
class AuthorityTest {

    private static final String RAW_AUTHORITY_CODE = "AUTHORITY_CODE";
    private static final AuthorityCode AUTHORITY_CODE = new AuthorityCode(RAW_AUTHORITY_CODE);

    private static final String DESCRIPTION = "DESCRIPTION";

    @Nested
    @DisplayName("권한 생성")
    class InitializeAuthority {

        @Nested
        @DisplayName("기본 권한 생성")
        class WhenCreatedBasicAuthority {
            private Authority authority;

            @BeforeEach
            void setup() {
                this.authority = Authority.createBasicAuthority(RAW_AUTHORITY_CODE, DESCRIPTION);
            }

            @Test
            @DisplayName("인자로 받은 코드를 저장해야 한다.")
            void shouldSaveGivenAuthorityCode() {
                assertEquals(AUTHORITY_CODE, this.authority.getCode());
            }

            @Test
            @DisplayName("인자로 받은 권한 설명을 저장해야 한다.")
            void shouldSaveGivenDescription() {
                assertEquals(DESCRIPTION, this.authority.getDescription());
            }

            @Test
            @DisplayName("기본권한 여부는 true를 반환해야 한다.")
            void shouldBasicReturnsTrue() {
                assertTrue(this.authority.isBasic());
            }
        }

        @Nested
        @DisplayName("일반적인 권한 생성")
        class WhenAuthority {
            private Authority authority;

            @BeforeEach
            void setup() {
                this.authority = Authority.createDefaultAuthority(RAW_AUTHORITY_CODE, DESCRIPTION);
            }

            @Test
            @DisplayName("인자로 받은 코드를 저장해야 한다.")
            void shouldSaveGivenAuthorityCode() {
                assertEquals(AUTHORITY_CODE, this.authority.getCode());
            }

            @Test
            @DisplayName("인자로 받은 권한 설명을 저장해야 한다.")
            void shouldSaveGivenDescription() {
                assertEquals(DESCRIPTION, this.authority.getDescription());
            }

            @Test
            @DisplayName("기본권한 여부는 false를 반환해야 한다.")
            void shouldBasicReturnsTrue() {
                assertFalse(this.authority.isBasic());
            }
        }
    }

}