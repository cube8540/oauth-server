package cube8540.oauth.authentication.credentials.authority.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("권한 도메인 테스트")
class AuthorityTest {

    private static final String RAW_AUTHORITY_CODE = "AUTHORITY_CODE";
    private static final AuthorityCode AUTHORITY_CODE = new AuthorityCode(RAW_AUTHORITY_CODE);

    private static final String DESCRIPTION = "DESCRIPTION";

    @Nested
    @DisplayName("기본 권한 설정")
    class SettingBasicAuthority {

        private Authority authority;

        @BeforeEach
        void setup() {
            this.authority = new Authority(RAW_AUTHORITY_CODE, DESCRIPTION);
        }

        @Nested
        @DisplayName("기본 권한으로 설정시")
        class ConfigBasicAuthority {
            @Test
            @DisplayName("기본 권한 여부가 true로 설정되어야 한다.")
            void shouldSettingBasicAuthority() {
                authority.settingBasicAuthority();

                assertTrue(authority.isBasic());
            }
        }

        @Nested
        @DisplayName("일반 권한으로 설정")
        class ConfigNotBasicAuthority {
            @Test
            @DisplayName("기본 권한 여부가 false로 설정되어야 한다.")
            void shouldSettingNotBasicAuthority() {
                authority.settingNotBasicAuthority();

                assertFalse(authority.isBasic());
            }
        }
    }
}