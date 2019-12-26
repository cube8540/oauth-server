package cube8540.oauth.authentication.users.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("인증키 테스트")
class UserCredentialsKeyTest {

    private static final String KEY_VALUE = "KEY-VALUE";
    private static final LocalDateTime NOT_EXPIRED_DATETIME = LocalDateTime.now().plusDays(1);
    private static final LocalDateTime EXPIRED_DATETIME = LocalDateTime.now().minusNanos(1);

    @Nested
    @DisplayName("키 매칭")
    class MatchedKey {

        @Nested
        @DisplayName("서로 다른 키 매칭")
        class WhenNotMatchedKey {
            private UserCredentialsKey key;

            @BeforeEach
            void setup() {
                this.key = new UserCredentialsKey(KEY_VALUE, NOT_EXPIRED_DATETIME);
            }

            @Test
            @DisplayName("결과값으로 NOT_MATCHED가 반환되어야 한다.")
            void shouldReturnsNotMatched() {
                UserKeyMatchedResult matchedResult = key.matches("NOT MATCHED KEY");
                assertEquals(UserKeyMatchedResult.NOT_MATCHED, matchedResult);
            }
        }

        @Nested
        @DisplayName("만료된 키 매칭")
        class WhenExpiredMatchedKey {
            private UserCredentialsKey key;

            @BeforeEach
            void setup() {
                this.key = new UserCredentialsKey(KEY_VALUE, EXPIRED_DATETIME);
            }

            @Test
            @DisplayName("결과값으로 EXPIRED가 반환되어야 한다.")
            void shouldReturnsExpired() {
                UserKeyMatchedResult matchedResult = key.matches(KEY_VALUE);
                assertEquals(UserKeyMatchedResult.EXPIRED, matchedResult);
            }
        }

        @Nested
        @DisplayName("서로 같은 키 매칭")
        class WhenMatchedKey {
            private UserCredentialsKey key;

            @BeforeEach
            void setup() {
                this.key = new UserCredentialsKey(KEY_VALUE, NOT_EXPIRED_DATETIME);
            }

            @Test
            @DisplayName("결과값으로 MATCHED가 반환되어야 한다.")
            void shouldReturnsMatched() {
                UserKeyMatchedResult matchedResult = key.matches(KEY_VALUE);
                assertEquals(UserKeyMatchedResult.MATCHED, matchedResult);
            }
        }
    }
}