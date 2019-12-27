package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuth2AuthorizedAccessTokenTest {

    private static final String RAW_AUTHENTICATION_ID = "AUTHENTICATION-ID";
    private static final OAuth2AuthenticationId AUTHENTICATION_ID = new OAuth2AuthenticationId(RAW_AUTHENTICATION_ID);

    private static final String RAW_TOKEN_ID = "TOKEN-ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final String RAW_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final LocalDateTime NOT_EXPIRED_EXPIRATION = LocalDateTime.now().plusDays(1);
    private static final LocalDateTime EXPIRED_EXPIRATION = LocalDateTime.now().minusNanos(1);

    private OAuth2Client client;
    private OAuth2AuthenticationIdGenerator authenticationIdGenerator;
    private OAuth2TokenIdGenerator tokenIdGenerator;

    @BeforeEach
    void setup() {
        this.client = mock(OAuth2Client.class);
        this.authenticationIdGenerator = mock(OAuth2AuthenticationIdGenerator.class);
        this.tokenIdGenerator = mock(OAuth2TokenIdGenerator.class);

        when(authenticationIdGenerator.extractAuthenticationValue()).thenReturn(AUTHENTICATION_ID);
        when(tokenIdGenerator.extractTokenValue()).thenReturn(TOKEN_ID);
    }

    @Nested
    @DisplayName("OAuth2 인증 토큰 생성")
    class InitializeOAuth2AuthorizedAccessToken {

        private OAuth2AuthorizedAccessToken accessToken;

        @BeforeEach
        void setup() {
            this.accessToken = new OAuth2AuthorizedAccessToken(authenticationIdGenerator, tokenIdGenerator,
                    RAW_EMAIL, client, NOT_EXPIRED_EXPIRATION);
        }

        @Test
        @DisplayName("인자로 받은 인증 아이디를 저장해야 한다.")
        void shouldSaveGivenAuthenticationId() {
            assertEquals(AUTHENTICATION_ID, accessToken.getAuthenticationId());
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
            assertEquals(client, accessToken.getClient());
        }

        @Test
        @DisplayName("인자로 받은 만료일을 저장해야 한다.")
        void shouldSaveGivenExpiration() {
            assertEquals(NOT_EXPIRED_EXPIRATION, accessToken.getExpiration());
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
                this.accessToken = new OAuth2AuthorizedAccessToken(authenticationIdGenerator, tokenIdGenerator,
                        RAW_EMAIL, client, EXPIRED_EXPIRATION);
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
                this.accessToken = new OAuth2AuthorizedAccessToken(authenticationIdGenerator, tokenIdGenerator,
                        RAW_EMAIL, client, NOT_EXPIRED_EXPIRATION);
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
                this.accessToken = new OAuth2AuthorizedAccessToken(authenticationIdGenerator, tokenIdGenerator,
                        RAW_EMAIL, client, EXPIRED_EXPIRATION);
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
            private final LocalDateTime expiredDateTime0 = LocalDateTime.now().plusSeconds(10);
            private final LocalDateTime expiredDateTime1 = LocalDateTime.now().plusSeconds(20);

            @Test
            @DisplayName("남은 시간이 초로 변환되어 반환되어야 한다.")
            void shouldReturnsSeconds() {
                OAuth2AuthorizedAccessToken accessToken0 = new OAuth2AuthorizedAccessToken(authenticationIdGenerator, tokenIdGenerator,
                        RAW_EMAIL, client, expiredDateTime0);
                OAuth2AuthorizedAccessToken accessToken1 = new OAuth2AuthorizedAccessToken(authenticationIdGenerator, tokenIdGenerator,
                        RAW_EMAIL, client, expiredDateTime1);

                assertEquals(Duration.between(LocalDateTime.now(), expiredDateTime0).toSeconds(), accessToken0.expiresIn());
                assertEquals(Duration.between(LocalDateTime.now(), expiredDateTime1).toSeconds(), accessToken1.expiresIn());
            }
        }
    }

    @Nested
    @DisplayName("토큰 추가 정보 저장")
    class WhenPutAdditionalInformation {
        private OAuth2AuthorizedAccessToken accessToken;

        @BeforeEach
        void setup() {
            this.accessToken = new OAuth2AuthorizedAccessToken(authenticationIdGenerator, tokenIdGenerator,
                    RAW_EMAIL, client, NOT_EXPIRED_EXPIRATION);
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
}