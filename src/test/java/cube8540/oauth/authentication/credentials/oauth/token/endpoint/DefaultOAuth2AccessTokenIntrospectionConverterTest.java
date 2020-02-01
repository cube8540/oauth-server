package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 엑세스 토큰")
class DefaultOAuth2AccessTokenIntrospectionConverterTest {

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final String RAW_USERNAME = "email@email.com";
    private static final UserEmail USERNAME = new UserEmail(RAW_USERNAME);

    private static final LocalDateTime EXPIRATION = LocalDateTime.of(2020, 2, 1, 22, 52);

    private static final Set<OAuth2ScopeId> SCOPE = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("SCOPE-1"),
            new OAuth2ScopeId("SCOPE-2"),
            new OAuth2ScopeId("SCOPE-3")
    ));

    private OAuth2AuthorizedAccessToken accessToken;
    private DefaultOAuth2AccessTokenIntrospectionConverter converter;

    @BeforeEach
    void setup() {
        this.accessToken = mock(OAuth2AuthorizedAccessToken.class);

        when(accessToken.getClient()).thenReturn(CLIENT_ID);
        when(accessToken.getEmail()).thenReturn(USERNAME);
        when(accessToken.getExpiration()).thenReturn(EXPIRATION);
        when(accessToken.getScope()).thenReturn(SCOPE);

        this.converter = new DefaultOAuth2AccessTokenIntrospectionConverter();
    }

    @Nested
    @DisplayName("엑세스 토큰 컨버팅")
    class AccessTokenConverting {

        @Test
        @DisplayName("active 플래그는 true로 설정되어야 한다.")
        void shouldActiveFlagIsTrue() {
            Map<String, Object> result = converter.convertAccessToken(accessToken);

            assertTrue(Boolean.parseBoolean(result.get(OAuth2Utils.AccessTokenIntrospectionKey.ACTIVE).toString()));
        }

        @Test
        @DisplayName("엑세스 토큰의 클라이언트 아이디를 반환해야 한다.")
        void shouldReturnsClientIdInAccessToken() {
            Map<String, Object> result = converter.convertAccessToken(accessToken);

            assertEquals(RAW_CLIENT_ID, result.get(OAuth2Utils.AccessTokenIntrospectionKey.CLIENT_ID));
        }

        @Test
        @DisplayName("엑세스 토큰의 유저 아이디를 반환해야 한다.")
        void shouldReturnsUsernameInAccessToken() {
            Map<String, Object> result = converter.convertAccessToken(accessToken);

            assertEquals(RAW_USERNAME, result.get(OAuth2Utils.AccessTokenIntrospectionKey.USERNAME));
        }

        @Test
        @DisplayName("토큰의 만료일을 Unix Timestamp로 변환하여 반환해야 한다.")
        void shouldReturnsTokenExpirationUnixTimestamp() {
            Map<String, Object> result = converter.convertAccessToken(accessToken);

            long expected = EXPIRATION.atZone(DEFAULT_TIME_ZONE.toZoneId()).toEpochSecond();
            assertEquals(expected, result.get(OAuth2Utils.AccessTokenIntrospectionKey.EXPIRATION));
        }

        @Test
        @DisplayName("토큰의 스코프를 반환해야 한다.")
        void shouldReturnsAccessTokenScope() {
            Map<String, Object> result = converter.convertAccessToken(accessToken);

            String expected = String.join(" ", SCOPE.stream().map(OAuth2ScopeId::getValue).collect(Collectors.toSet()));
            assertEquals(expected, result.get(OAuth2Utils.AccessTokenIntrospectionKey.SCOPE));
        }

        @Nested
        @DisplayName("엑세스 토큰의 유저 아이디가 null 일시")
        class WhenAccessTokenUsernameIsNull {
            private OAuth2AuthorizedAccessToken accessToken;

            @BeforeEach
            void setup() {
                this.accessToken = mock(OAuth2AuthorizedAccessToken.class);

                when(accessToken.getClient()).thenReturn(CLIENT_ID);
                when(accessToken.getEmail()).thenReturn(null);
                when(accessToken.getExpiration()).thenReturn(EXPIRATION);
                when(accessToken.getScope()).thenReturn(SCOPE);
            }

            @Test
            @DisplayName("유저 아이디를 null로 설정해야 한다.")
            void shouldSetUsernameNull() {
                Map<String, Object> result = converter.convertAccessToken(accessToken);

                assertNull(result.get(OAuth2Utils.AccessTokenIntrospectionKey.USERNAME));
            }
        }
    }
}