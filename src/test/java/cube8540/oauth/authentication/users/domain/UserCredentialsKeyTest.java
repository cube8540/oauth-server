package cube8540.oauth.authentication.users.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.LocalDateTime;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("인증키 테스트")
class UserCredentialsKeyTest {

    private static final String KEY_VALUE = "KEY-VALUE";

    private static final LocalDateTime NOW = LocalDateTime.of(2020, 2, 8, 23, 5);
    private static final LocalDateTime EXPIRATION_DATETIME = NOW.plusMinutes(5);

    @Nested
    @DisplayName("키 생성")
    class CreateNewKey {

        private UserCredentialsKey key;

        @BeforeEach
        void setup() {
            Clock clock = Clock.fixed(NOW.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
            UserCredentialsKey.setClock(clock);

            this.key = new UserCredentialsKey(KEY_VALUE);
        }

        @Test
        @DisplayName("인자로 받은 키값을 저장해야 한다.")
        void shouldSaveKeyValueForArguments() {
            assertEquals(KEY_VALUE, key.getKeyValue());
        }

        @Test
        @DisplayName("만료시간은 현재시간 + 5분 이어야 한다.")
        void shouldExpirationDateTimeIsNowPlus5Minute() {
            assertEquals(EXPIRATION_DATETIME, key.getExpiryDateTime());
        }
    }

    @Nested
    @DisplayName("키 매칭")
    class MatchedKey {

        @Nested
        @DisplayName("서로 다른 키 매칭")
        class WhenNotMatchedKey {
            private UserCredentialsKey key;

            @BeforeEach
            void setup() {
                Clock registeredClock = Clock.fixed(NOW.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(registeredClock);

                this.key = new UserCredentialsKey(KEY_VALUE);

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(clock);
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
                Clock registeredClock = Clock.fixed(NOW.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(registeredClock);

                this.key = new UserCredentialsKey(KEY_VALUE);

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.plusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(clock);
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
                Clock registeredClock = Clock.fixed(NOW.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(registeredClock);

                this.key = new UserCredentialsKey(KEY_VALUE);

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(clock);
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