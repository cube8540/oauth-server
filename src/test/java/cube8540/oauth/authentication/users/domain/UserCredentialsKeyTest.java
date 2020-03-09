package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.AuthenticationApplication;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("인증키 테스트")
class UserCredentialsKeyTest {

    @Nested
    @DisplayName("키 생성")
    class CreateNewKey {

        private UserCredentialsKey key;

        @BeforeEach
        void setup() {
            Clock clock = Clock.fixed(UserTestHelper.NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
            UserCredentialsKey.setClock(clock);

            this.key = new UserCredentialsKey(UserTestHelper.RAW_CREDENTIALS_KEY);
        }

        @Test
        @DisplayName("만료시간은 현재시간 + 5분 이어야 한다.")
        void shouldExpirationDateTimeIsNowPlus5Minute() {
            Assertions.assertEquals(UserTestHelper.EXPIRATION_DATETIME, key.getExpiryDateTime());
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
                Clock registeredClock = Clock.fixed(UserTestHelper.NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(registeredClock);

                this.key = new UserCredentialsKey(UserTestHelper.RAW_CREDENTIALS_KEY);
            }

            @Test
            @DisplayName("결과값으로 NOT_MATCHED 가 반환되어야 한다.")
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
                Clock registeredClock = Clock.fixed(UserTestHelper.NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(registeredClock);

                this.key = new UserCredentialsKey(UserTestHelper.RAW_CREDENTIALS_KEY);

                Clock clock = Clock.fixed(UserTestHelper.NOT_EXPIRATION_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(clock);
            }

            @Test
            @DisplayName("결과값으로 EXPIRED 가 반환되어야 한다.")
            void shouldReturnsExpired() {
                UserKeyMatchedResult matchedResult = key.matches(UserTestHelper.RAW_CREDENTIALS_KEY);

                assertEquals(UserKeyMatchedResult.EXPIRED, matchedResult);
            }
        }

        @Nested
        @DisplayName("서로 같은 키 매칭")
        class WhenMatchedKey {
            private UserCredentialsKey key;

            @BeforeEach
            void setup() {
                Clock registeredClock = Clock.fixed(UserTestHelper.NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(registeredClock);

                this.key = new UserCredentialsKey(UserTestHelper.RAW_CREDENTIALS_KEY);

                Clock clock = Clock.fixed(UserTestHelper.EXPIRATION_DATETIME.minusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                UserCredentialsKey.setClock(clock);
            }

            @Test
            @DisplayName("결과값으로 MATCHED 가 반환되어야 한다.")
            void shouldReturnsMatched() {
                UserKeyMatchedResult matchedResult = key.matches(UserTestHelper.RAW_CREDENTIALS_KEY);

                assertEquals(UserKeyMatchedResult.MATCHED, matchedResult);
            }
        }
    }
}