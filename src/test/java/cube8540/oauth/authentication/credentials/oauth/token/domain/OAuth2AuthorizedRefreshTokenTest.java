package cube8540.oauth.authentication.credentials.oauth.token.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.LocalDateTime;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("리플레시 토큰 도메인 테스트")
class OAuth2AuthorizedRefreshTokenTest {

    private static final String RAW_TOKEN_ID = "TOKEN_ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final LocalDateTime EXPIRATION = LocalDateTime.of(2020, 1, 29, 22, 27);

    private OAuth2AuthorizedAccessToken accessToken;
    private OAuth2TokenIdGenerator tokenIdGenerator;

    @BeforeEach
    void setup() {
        this.tokenIdGenerator = mock(OAuth2TokenIdGenerator.class);
        this.accessToken = mock(OAuth2AuthorizedAccessToken.class);
    }

    @Nested
    @DisplayName("리플래시 토큰 생성")
    class InitializeRefreshToken {

        private OAuth2AuthorizedRefreshToken refreshToken;

        @BeforeEach
        void setup() {
            when(tokenIdGenerator.generateTokenValue()).thenReturn(TOKEN_ID);
            this.refreshToken = new OAuth2AuthorizedRefreshToken(tokenIdGenerator, EXPIRATION, accessToken);
        }

        @Test
        @DisplayName("인자로 받은 토큰 아이디를 저장해야 한다.")
        void shouldSaveGivenTokenId() {
            assertEquals(TOKEN_ID, refreshToken.getTokenId());
        }

        @Test
        @DisplayName("인자로 받은 만료일을 저장해야 한다.")
        void shouldSaveGivenExpiration() {
            assertEquals(EXPIRATION, refreshToken.getExpiration());
        }

        @Test
        @DisplayName("인자로 받은 액세스 토큰을 저장해야 한다.")
        void shouldSaveGivenAccessToken() {
            assertEquals(accessToken, refreshToken.getAccessToken());
        }
    }

    @Nested
    @DisplayName("리플래시 토큰 만료 여부 검사")
    class RefreshTokenExpiredValidate {

        private OAuth2AuthorizedRefreshToken refreshToken;

        @BeforeEach
        void setup() {
            when(tokenIdGenerator.generateTokenValue()).thenReturn(TOKEN_ID);
        }

        @Nested
        @DisplayName("현재 시간이 만료일을 초과했을시")
        class WhenRefreshTokenExpired {

            @BeforeEach
            void setup() {
                Clock clock = Clock.fixed(EXPIRATION.plusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());

                refreshToken = new OAuth2AuthorizedRefreshToken(tokenIdGenerator, EXPIRATION, accessToken);
                OAuth2AuthorizedRefreshToken.setClock(clock);
            }

            @Test
            @DisplayName("토큰 만료 검사시 true가 반환되어야 한다.")
            void shouldIsExpiredReturnsTrue() {
                assertTrue(refreshToken.isExpired());
            }
        }

        @Nested
        @DisplayName("현재 시간이 만료일을 초과하지 않았을시")
        class WhenRefreshTokenNotExpired {

            @BeforeEach
            void setup() {
                Clock clock = Clock.fixed(EXPIRATION.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());

                refreshToken = new OAuth2AuthorizedRefreshToken(tokenIdGenerator, EXPIRATION, accessToken);
                OAuth2AuthorizedRefreshToken.setClock(clock);
            }

            @Test
            @DisplayName("토큰 만료 검사시 false가 반환되어야 한다.")
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
                when(tokenIdGenerator.generateTokenValue()).thenReturn(TOKEN_ID);

                Clock clock = Clock.fixed(EXPIRATION.plusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
                this.refreshToken = new OAuth2AuthorizedRefreshToken(tokenIdGenerator, EXPIRATION, accessToken);
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
                when(tokenIdGenerator.generateTokenValue()).thenReturn(TOKEN_ID);

                Clock clock = Clock.fixed(EXPIRATION.minusSeconds(expiresIn).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
                this.refreshToken = new OAuth2AuthorizedRefreshToken(tokenIdGenerator, EXPIRATION, accessToken);
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