package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.EXPIRATION;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.RAW_USERNAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("기본 엑세스 토큰")
class DefaultOAuth2AccessTokenIntrospectionConverterTest {

    @Nested
    @DisplayName("엑세스 토큰 컨버팅")
    class AccessTokenConverting {

        @Nested
        @DisplayName("엑세스 토큰이 클라이언트 인증을 통해 생성된 엑세스 토큰일때")
        class WhenAccessTokenCreatedByClientCredentials extends AccessTokenAssertSetup {

            @Override
            protected void configAccessToken(TokenEndpointTestHelper.MockAccessToken mockAccessToken) {
                mockAccessToken.configClientAuthentication();
            }

            @Test
            @DisplayName("유저 아이디를 null 로 설정해야 한다.")
            void shouldSetUsernameNull() {
                Map<String, Object> result = converter.convertAccessToken(accessToken);

                assertNull(result.get(OAuth2Utils.AccessTokenIntrospectionKey.USERNAME));
            }
        }

        @Nested
        @DisplayName("엑세스 토큰이 클라이언트 인증을 통해 생성된 토큰이 아닐시")
        class WhenAccessTokenCreatedByNotClientCredentials extends AccessTokenAssertSetup {

            @Test
            @DisplayName("엑세스 토큰의 유저 아이디를 반환해야 한다.")
            void shouldReturnsUsernameInAccessToken() {
                Map<String, Object> result = converter.convertAccessToken(accessToken);

                Assertions.assertEquals(RAW_USERNAME, result.get(OAuth2Utils.AccessTokenIntrospectionKey.USERNAME));
            }
        }
    }

    private static abstract class AccessTokenAssertSetup {
        protected OAuth2AccessTokenDetails accessToken;
        protected DefaultOAuth2AccessTokenIntrospectionConverter converter;

        @BeforeEach
        void setup() {
            TokenEndpointTestHelper.MockAccessToken mockAccessToken = TokenEndpointTestHelper.mockAccessToken().configDefault();

            configAccessToken(mockAccessToken);

            this.accessToken = mockAccessToken.build();
            this.converter = new DefaultOAuth2AccessTokenIntrospectionConverter();
        }

        protected void configAccessToken(TokenEndpointTestHelper.MockAccessToken mockAccessToken) {}

        @Test
        @DisplayName("active 플래그는 true 로 설정되어야 한다.")
        void shouldActiveFlagIsTrue() {
            Map<String, Object> result = converter.convertAccessToken(accessToken);

            assertTrue(Boolean.parseBoolean(result.get(OAuth2Utils.AccessTokenIntrospectionKey.ACTIVE).toString()));
        }

        @Test
        @DisplayName("엑세스 토큰의 클라이언트 아이디를 반환해야 한다.")
        void shouldReturnsClientIdInAccessToken() {
            Map<String, Object> result = converter.convertAccessToken(accessToken);

            Assertions.assertEquals(RAW_CLIENT_ID, result.get(OAuth2Utils.AccessTokenIntrospectionKey.CLIENT_ID));
        }

        @Test
        @DisplayName("토큰의 만료일을 Unix Timestamp 로 변환하여 반환해야 한다.")
        void shouldReturnsTokenExpirationUnixTimestamp() {
            Map<String, Object> result = converter.convertAccessToken(accessToken);

            long expected = EXPIRATION.atZone(DEFAULT_TIME_ZONE.toZoneId()).toEpochSecond();
            assertEquals(expected, result.get(OAuth2Utils.AccessTokenIntrospectionKey.EXPIRATION));
        }

        @Test
        @DisplayName("토큰의 스코프를 반환해야 한다.")
        void shouldReturnsAccessTokenScope() {
            Map<String, Object> result = converter.convertAccessToken(accessToken);

            String expected = String.join(" ", RAW_SCOPES);
            assertEquals(expected, result.get(OAuth2Utils.AccessTokenIntrospectionKey.SCOPE));
        }
    }
}