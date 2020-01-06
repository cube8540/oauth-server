package cube8540.oauth.authentication.credentials.oauth.token.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("리플레시 토큰 도메인 테스트")
class OAuth2AuthorizedRefreshTokenTest {

    private static final String RAW_TOKEN_ID = "TOKEN_ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final LocalDateTime NOT_EXPIRED_EXPIRATION = LocalDateTime.now().plusDays(1);
    private static final LocalDateTime EXPIRED_EXPIRATION = LocalDateTime.now().minusNanos(1);

    private OAuth2TokenIdGenerator tokenIdGenerator;

    @BeforeEach
    void setup() {
        this.tokenIdGenerator = mock(OAuth2TokenIdGenerator.class);
    }

    @Nested
    @DisplayName("리플래시 토큰 생성")
    class InitializeRefreshToken {

        private OAuth2AuthorizedRefreshToken refreshToken;

        @BeforeEach
        void setup() {
            when(tokenIdGenerator.generateTokenValue()).thenReturn(TOKEN_ID);
            this.refreshToken = new OAuth2AuthorizedRefreshToken(tokenIdGenerator, NOT_EXPIRED_EXPIRATION);
        }

        @Test
        @DisplayName("인자로 받은 토큰 아이디를 저장해야 한다.")
        void shouldSaveGivenTokenId() {
            assertEquals(TOKEN_ID, refreshToken.getTokenId());
        }

        @Test
        @DisplayName("인자로 받은 만료일을 저장해야 한다.")
        void shouldSaveGivenExpiration() {
            assertEquals(NOT_EXPIRED_EXPIRATION, refreshToken.getExpiration());
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
                refreshToken = new OAuth2AuthorizedRefreshToken(tokenIdGenerator, EXPIRED_EXPIRATION);
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
                refreshToken = new OAuth2AuthorizedRefreshToken(tokenIdGenerator, NOT_EXPIRED_EXPIRATION);
            }

            @Test
            @DisplayName("토큰 만료 검사시 false가 반환되어야 한다.")
            void shouldIsExpiredReturnsFalse() {
                assertFalse(refreshToken.isExpired());
            }
        }
    }
}