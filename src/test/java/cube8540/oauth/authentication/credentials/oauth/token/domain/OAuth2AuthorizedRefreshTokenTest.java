package cube8540.oauth.authentication.credentials.oauth.token.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.REFRESH_EXPIRATION_DATETIME;
import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.configRefreshTokenIdGenerator;
import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.mockAccessToken;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("리플레시 토큰 도메인 테스트")
class OAuth2AuthorizedRefreshTokenTest {

    @Nested
    @DisplayName("리플래시 토큰 만료 여부 검사")
    class RefreshTokenExpiredValidate {

        @Nested
        @DisplayName("현재 시간이 만료일을 초과했을시")
        class WhenRefreshTokenExpired {
            private OAuth2AuthorizedRefreshToken refreshToken;

            @BeforeEach
            void setup() {
                Clock clock = Clock.fixed(REFRESH_EXPIRATION_DATETIME.plusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());

                this.refreshToken = new OAuth2AuthorizedRefreshToken(configRefreshTokenIdGenerator(), REFRESH_EXPIRATION_DATETIME, mockAccessToken());
                OAuth2AuthorizedRefreshToken.setClock(clock);
            }

            @Test
            @DisplayName("토큰 만료 검사시 true 가 반환되어야 한다.")
            void shouldIsExpiredReturnsTrue() {
                assertTrue(refreshToken.isExpired());
            }
        }

        @Nested
        @DisplayName("현재 시간이 만료일을 초과하지 않았을시")
        class WhenRefreshTokenNotExpired {
            private OAuth2AuthorizedRefreshToken refreshToken;

            @BeforeEach
            void setup() {
                Clock clock = Clock.fixed(REFRESH_EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());

                this.refreshToken = new OAuth2AuthorizedRefreshToken(configRefreshTokenIdGenerator(), REFRESH_EXPIRATION_DATETIME, mockAccessToken());
                OAuth2AuthorizedRefreshToken.setClock(clock);
            }

            @Test
            @DisplayName("토큰 만료 검사시 false 가 반환되어야 한다.")
            void shouldIsExpiredReturnsFalse() {
                assertFalse(refreshToken.isExpired());
            }
        }
    }

    @Nested
    @DisplayName("토큰 만료까지 남은 기간 검색")
    class WhenExpiresIn {

        @Nested
        @DisplayName("현재 시간이 만료일을 초과했을시")
        class WhenAccessTokenExpired {
            private OAuth2AuthorizedRefreshToken refreshToken;

            @BeforeEach
            void setup() {
                Clock clock = Clock.fixed(REFRESH_EXPIRATION_DATETIME.plusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());

                this.refreshToken = new OAuth2AuthorizedRefreshToken(configRefreshTokenIdGenerator(), REFRESH_EXPIRATION_DATETIME, mockAccessToken());
                OAuth2AuthorizedRefreshToken.setClock(clock);
            }

            @Test
            @DisplayName("0 이 반환되어야 한다.")
            void shouldReturns0() {
                long expiresIn = refreshToken.expiresIn();

                assertEquals(0, expiresIn);
            }
        }

        @Nested
        @DisplayName("현재 시간이 만료일을 초과하지 않았을시")
        class WhenAccessTokenNotExpired {
            private OAuth2AuthorizedRefreshToken refreshToken;
            private long expiresIn = 10;

            @BeforeEach
            void setup() {
                Clock clock = Clock.fixed(REFRESH_EXPIRATION_DATETIME.minusSeconds(expiresIn).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());

                this.refreshToken = new OAuth2AuthorizedRefreshToken(configRefreshTokenIdGenerator(), REFRESH_EXPIRATION_DATETIME, mockAccessToken());
                OAuth2AuthorizedRefreshToken.setClock(clock);
            }


            @Test
            @DisplayName("남은 시간이 초로 변환되어 반환되어야 한다.")
            void shouldReturnsSeconds() {
                assertEquals(expiresIn, refreshToken.expiresIn());
            }
        }
    }
}