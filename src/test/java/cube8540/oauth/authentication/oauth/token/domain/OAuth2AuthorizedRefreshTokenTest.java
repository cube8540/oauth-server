package cube8540.oauth.authentication.oauth.token.domain;

import cube8540.oauth.authentication.AuthenticationApplication;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;

import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenTestHelper.REFRESH_EXPIRATION_DATETIME;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenTestHelper.makeAccessToken;
import static cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenTestHelper.makeRefreshTokenIdGenerator;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("리플레시 토큰 도메인 테스트")
class OAuth2AuthorizedRefreshTokenTest {

    @Test
    @DisplayName("현재 시간이 만료일을 초과 했을시")
    void whenCurrentTimeExceedsExpirationDate() {
        OAuth2AuthorizedRefreshToken refreshToken = new OAuth2AuthorizedRefreshToken(makeRefreshTokenIdGenerator(), REFRESH_EXPIRATION_DATETIME, makeAccessToken());

        Clock clock = Clock.fixed(REFRESH_EXPIRATION_DATETIME.plusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
        OAuth2AuthorizedRefreshToken.setClock(clock);

        assertTrue(refreshToken.isExpired());
        assertEquals(0, refreshToken.expiresIn());
    }

    @Test
    @DisplayName("현재 시간이 만료일을 초과 하지 않을시")
    void whenCurrentTimeNotExceedsExpirationDate() {
        OAuth2AuthorizedRefreshToken refreshToken = new OAuth2AuthorizedRefreshToken(makeRefreshTokenIdGenerator(), REFRESH_EXPIRATION_DATETIME, makeAccessToken());

        long expiresIn = 10;
        Clock clock = Clock.fixed(REFRESH_EXPIRATION_DATETIME.minusSeconds(expiresIn).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
        OAuth2AuthorizedRefreshToken.setClock(clock);

        assertFalse(refreshToken.isExpired());
        assertEquals(expiresIn, refreshToken.expiresIn());
    }
}