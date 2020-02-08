package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 액세스 토큰 도메인 테스트")
class OAuth2AuthorizedAccessTokenTest {

    private static final String RAW_TOKEN_ID = "TOKEN-ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final String RAW_REFRESH_TOKEN_ID = "REFRESH_TOKEN-ID";
    private static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    private static final String RAW_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final AuthorizationGrantType GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE;

    private static final LocalDateTime EXPIRATION_DATETIME = LocalDateTime.of(2020, 1, 29, 22, 51);

    private static final Set<OAuth2ScopeId> SCOPE_ID = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("SCOPE-1"),
            new OAuth2ScopeId("SCOPE-2"),
            new OAuth2ScopeId("SCOPE-3")
    ));

    private OAuth2TokenIdGenerator tokenIdGenerator;

    @BeforeEach
    void setup() {
        this.tokenIdGenerator = mock(OAuth2TokenIdGenerator.class);

        when(tokenIdGenerator.generateTokenValue()).thenReturn(TOKEN_ID);
    }

    @Nested
    @DisplayName("OAuth2 인증 토큰 생성")
    class InitializeOAuth2AuthorizedAccessToken {

        private OAuth2AuthorizedAccessToken accessToken;

        @BeforeEach
        void setup() {
            this.accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                    .email(EMAIL).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME)
                    .scope(SCOPE_ID).build();
        }

        @Test
        @DisplayName("인자로 받은 토큰 아이디를 저장해야 한다.")
        void shouldSaveGivenTokenId() {
            assertEquals(TOKEN_ID, accessToken.getTokenId());
        }

        @Test
        @DisplayName("인자로 받은 이메일을 저장해야 한다.")
        void shouldSaveGivenEmail() {
            assertEquals(EMAIL, accessToken.getEmail());
        }

        @Test
        @DisplayName("인자로 받은 클라이언트를 저장해야 한다.")
        void shouldSaveGivenClient() {
            assertEquals(CLIENT_ID, accessToken.getClient());
        }

        @Test
        @DisplayName("인자로 받은 인증 타입을 저장해야 한다.")
        void shouldSaveGivenGrantType() {
            assertEquals(GRANT_TYPE, accessToken.getTokenGrantType());
        }

        @Test
        @DisplayName("인자로 받은 만료일을 저장해야 한다.")
        void shouldSaveGivenExpiration() {
            assertEquals(EXPIRATION_DATETIME, accessToken.getExpiration());
        }

        @Test
        @DisplayName("인자로 받은 스코프를 저장해야 한다.")
        void shouldSaveGivenScope() {
            boolean isContains = accessToken.getScope().containsAll(SCOPE_ID);
            assertTrue(isContains);
        }
    }

    @Nested
    @DisplayName("OAuth2 인증 토큰 만료일 검사")
    class ValidateExpiration {

        @Nested
        @DisplayName("현재 시간이 만료일을 초과 했을시")
        class WhenAccessTokenExpired {
            private OAuth2AuthorizedAccessToken accessToken;

            @BeforeEach
            void setup() {
                this.accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                        .email(EMAIL).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.plusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
                OAuth2AuthorizedAccessToken.setClock(clock);
            }

            @Test
            @DisplayName("만료 여부 검사시 true를 반환해야 한다.")
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
                this.accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                        .email(EMAIL).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.minusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
                OAuth2AuthorizedAccessToken.setClock(clock);
            }

            @Test
            @DisplayName("만료 여부 검사시 false를 반환해야 한다.")
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
                this.accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                        .email(EMAIL).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.plusNanos(1).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
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
                this.accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                        .email(EMAIL).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();

                Clock clock = Clock.fixed(EXPIRATION_DATETIME.minusSeconds(expiresIn).toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
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
            this.accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                    .email(EMAIL).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();
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
        private LocalDateTime expirationDateTime = LocalDateTime.of(2020, 1, 29, 11, 9);
        private OAuth2AuthorizedAccessToken accessToken;

        @BeforeEach
        void setup() {
            this.accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                    .email(EMAIL).client(CLIENT_ID).tokenGrantType(GRANT_TYPE).expiration(EXPIRATION_DATETIME).build();

            this.refreshTokenIdGenerator = mock(OAuth2TokenIdGenerator.class);
            when(refreshTokenIdGenerator.generateTokenValue()).thenReturn(REFRESH_TOKEN_ID);
        }

        @Test
        @DisplayName("리플래시 토큰을 생성하여 저장한다.")
        void shouldCreateAndSaveRefreshToken() {
            this.accessToken.generateRefreshToken(refreshTokenIdGenerator, expirationDateTime);

            OAuth2AuthorizedRefreshToken refreshToken = this.accessToken.getRefreshToken();
            assertEquals(REFRESH_TOKEN_ID, refreshToken.getTokenId());
            assertEquals(expirationDateTime, refreshToken.getExpiration());
        }

        @Test
        @DisplayName("리플래시 토큰에 연관된 엑세스 토큰을 리플래스 토큰을 생성한 엑세스 토큰이어야 한다.")
        void shouldRefreshTokenAssociationAccessTokenIsParentAccessToken() {
            this.accessToken.generateRefreshToken(refreshTokenIdGenerator, expirationDateTime);

            OAuth2AuthorizedRefreshToken refreshToken = this.accessToken.getRefreshToken();
            assertEquals(accessToken, refreshToken.getAccessToken());
        }
    }
}