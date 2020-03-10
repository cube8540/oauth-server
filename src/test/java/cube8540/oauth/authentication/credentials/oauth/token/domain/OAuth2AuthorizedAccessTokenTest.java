package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.AuthenticationApplication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;

import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.EXPIRATION_DATETIME;
import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.GRANT_TYPE;
import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.REFRESH_EXPIRATION_DATETIME;
import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.REFRESH_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.configAccessTokenIdGenerator;
import static cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenTestHelper.configRefreshTokenIdGenerator;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OAuth2 액세스 토큰 도메인 테스트")
class OAuth2AuthorizedAccessTokenTest {

    @Nested
    @DisplayName("OAuth2 인증 토큰 만료일 검사")
    class ValidateExpiration {

        @Nested
        @DisplayName("현재 시간이 만료일을 초과 했을시")
        class WhenAccessTokenExpired {
            private OAuth2AuthorizedAccessToken accessToken;

            @BeforeEach
            void setup() {
                this.accessToken = OAuth2AuthorizedAccessToken.builder(configAccessTokenIdGenerator())
                        .username(USERNAME).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.plusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                OAuth2AuthorizedAccessToken.setClock(clock);
            }

            @Test
            @DisplayName("만료 여부 검사시 true 를 반환해야 한다.")
            void shouldValidateExpiredReturnsTrue() {
                boolean isExpired = accessToken.isExpired();

                assertTrue(isExpired);
            }
        }

        @Nested
        @DisplayName("현재 시간이 만료일을 초과하지 않았을시")
        class WhenAccessTokenNotExpired {
            private OAuth2AuthorizedAccessToken accessToken;

            @BeforeEach
            void setup() {
                this.accessToken = OAuth2AuthorizedAccessToken.builder(configAccessTokenIdGenerator())
                        .username(USERNAME).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                OAuth2AuthorizedAccessToken.setClock(clock);
            }

            @Test
            @DisplayName("만료 여부 검사시 false 를 반환해야 한다.")
            void shouldValidateExpiredReturnsFalse() {
                boolean isExpired = accessToken.isExpired();

                assertFalse(isExpired);
            }
        }
    }

    @Nested
    @DisplayName("토큰 만료까지 남은 기간 검색")
    class WhenExpiresIn {

        @Nested
        @DisplayName("현재 시간이 만료일을 초과했을시")
        class WhenAccessTokenExpired {
            private OAuth2AuthorizedAccessToken accessToken;

            @BeforeEach
            void setup() {
                this.accessToken = OAuth2AuthorizedAccessToken.builder(configAccessTokenIdGenerator())
                        .username(USERNAME).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.plusNanos(1).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                OAuth2AuthorizedAccessToken.setClock(clock);
            }

            @Test
            @DisplayName("0 이 반환되어야 한다.")
            void shouldReturns0() {
                long expiresIn = accessToken.expiresIn();

                assertEquals(0, expiresIn);
            }
        }

        @Nested
        @DisplayName("현재 시간이 만료일을 초과하지 않았을시")
        class WhenAccessTokenNotExpired {
            private OAuth2AuthorizedAccessToken accessToken;
            private long expiresIn = 10;

            @BeforeEach
            void setup() {
                this.accessToken = OAuth2AuthorizedAccessToken.builder(configAccessTokenIdGenerator())
                        .username(USERNAME).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.minusSeconds(expiresIn).toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
                OAuth2AuthorizedAccessToken.setClock(clock);
            }


            @Test
            @DisplayName("남은 시간이 초로 변환되어 반환되어야 한다.")
            void shouldReturnsSeconds() {
                assertEquals(expiresIn, accessToken.expiresIn());
            }
        }
    }

    @Nested
    @DisplayName("토큰 추가 정보 저장")
    class WhenPutAdditionalInformation {
        private OAuth2AuthorizedAccessToken accessToken;

        @BeforeEach
        void setup() {
            this.accessToken = OAuth2AuthorizedAccessToken.builder(configAccessTokenIdGenerator())
                    .username(USERNAME).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();
        }

        @Test
        @DisplayName("인자로 받은 키와 값이 저장되어 있어야 한다.")
        void shouldSaveGivenKeyValues() {
            accessToken.putAdditionalInformation("KEY-0", "VALUE-0");
            accessToken.putAdditionalInformation("KEY-1", "VALUE-1");

            assertTrue(accessToken.getAdditionalInformation().containsKey("KEY-0"));
            assertTrue(accessToken.getAdditionalInformation().containsKey("KEY-1"));
            assertEquals("VALUE-0", accessToken.getAdditionalInformation().get("KEY-0"));
            assertEquals("VALUE-1", accessToken.getAdditionalInformation().get("KEY-1"));
        }
    }

    @Nested
    @DisplayName("리플래시 토큰 생성 및 저장")
    class CreateAndSaveRefreshToken {
        private OAuth2TokenIdGenerator refreshTokenIdGenerator;
        private OAuth2AuthorizedAccessToken accessToken;

        @BeforeEach
        void setup() {
            this.accessToken = OAuth2AuthorizedAccessToken.builder(configAccessTokenIdGenerator())
                    .username(USERNAME).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();
            this.refreshTokenIdGenerator = configRefreshTokenIdGenerator();
        }

        @Test
        @DisplayName("리플래시 토큰을 생성하여 저장한다.")
        void shouldCreateAndSaveRefreshToken() {
            this.accessToken.generateRefreshToken(refreshTokenIdGenerator, REFRESH_EXPIRATION_DATETIME);

            OAuth2AuthorizedRefreshToken refreshToken = this.accessToken.getRefreshToken();
            assertEquals(REFRESH_TOKEN_ID, refreshToken.getTokenId());
            assertEquals(REFRESH_EXPIRATION_DATETIME, refreshToken.getExpiration());
        }

        @Test
        @DisplayName("리플래시 토큰에 연관된 엑세스 토큰을 리플래스 토큰을 생성한 엑세스 토큰이어야 한다.")
        void shouldRefreshTokenAssociationAccessTokenIsParentAccessToken() {
            this.accessToken.generateRefreshToken(refreshTokenIdGenerator, REFRESH_EXPIRATION_DATETIME);

            OAuth2AuthorizedRefreshToken refreshToken = this.accessToken.getRefreshToken();
            assertEquals(accessToken, refreshToken.getAccessToken());
        }
    }
}