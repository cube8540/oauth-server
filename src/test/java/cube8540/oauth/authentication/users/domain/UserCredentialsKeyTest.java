package cube8540.oauth.authentication.users.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static cube8540.oauth.authentication.users.domain.UserTestHelper.EXPIRATION_DATETIME;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.RAW_CREDENTIALS_KEY;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makeDefaultClock;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makeExpiredClock;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("인증키 테스트")
class UserCredentialsKeyTest {

    @Test
    @DisplayName("새로운 키 생성")
    void createNewKey() {
        UserCredentialsKey.setClock(makeDefaultClock());

        UserCredentialsKey key = new UserCredentialsKey(RAW_CREDENTIALS_KEY);
        assertEquals(EXPIRATION_DATETIME, key.getExpiryDateTime());
    }

    @Test
    @DisplayName("서로 다른 키 매칭")
    void matchedDifferentKey() {
        UserCredentialsKey.setClock(makeDefaultClock());
        UserCredentialsKey key = new UserCredentialsKey(RAW_CREDENTIALS_KEY);

        UserKeyMatchedResult result = key.matches("NOT MATCHED KEY");
        assertEquals(UserKeyMatchedResult.NOT_MATCHED, result);
    }

    @Test
    @DisplayName("만료된 키 매칭")
    void matchedExpiredKey() {
        UserCredentialsKey.setClock(makeDefaultClock());
        UserCredentialsKey key = new UserCredentialsKey(RAW_CREDENTIALS_KEY);

        UserCredentialsKey.setClock(makeExpiredClock());

        UserKeyMatchedResult result = key.matches(RAW_CREDENTIALS_KEY);
        assertEquals(UserKeyMatchedResult.EXPIRED, result);
    }

    @Test
    @DisplayName("옳바른 키 매칭")
    void matchedAllowedKey() {
        UserCredentialsKey.setClock(makeDefaultClock());
        UserCredentialsKey key = new UserCredentialsKey(RAW_CREDENTIALS_KEY);

        UserKeyMatchedResult result = key.matches(RAW_CREDENTIALS_KEY);
        assertEquals(UserKeyMatchedResult.MATCHED, result);
    }
}