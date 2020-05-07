package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.Clock;
import java.util.Set;
import java.util.stream.Collectors;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.USERNAME;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("암묵적 동의를 통한 토큰 부여 테스트")
class ImplicitTokenGranterTest {

    @Nested
    @DisplayName("엑세스 토큰 생성")
    class CreateAccessToken {

        @Nested
        @DisplayName("요청 스코프가 null 일시")
        class WhenRequestScopeIsNull extends AccessTokenGranterSetup {

            @Override
            protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest request) {
                request.configDefaultUsername().configNullScopes();
            }

            @Test
            @DisplayName("토큰의 스코프는 ClientDetails 에 저장된 스코프어야 한다.")
            void shouldScopeIsStoredInClientDetails() {
                OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(CLIENT_SCOPES, accessToken.getScopes());
            }
        }

        @Nested
        @DisplayName("요청 스코프가 비어있을시")
        class WhenRequestEmptyScope extends AccessTokenGranterSetup {

            @Override
            protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                tokenRequest.configDefaultUsername().configEmptyScopes();
            }

            @Test
            @DisplayName("토큰의 스코프는 ClientDetails 에 저장된 스코프어야 한다.")
            void shouldScopeIsStoredInClientDetails() {
                OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                Assertions.assertEquals(OAuth2TokenApplicationTestHelper.CLIENT_SCOPES, accessToken.getScopes());
            }
        }

        @Nested
        @DisplayName("요청 스코프가 null 이 아니며 비어있지 않을시")
        class WhenRequestScopeNotNullAndNotEmpty extends AccessTokenGranterSetup {

            @Override
            protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest request) {
                request.configDefaultScopes().configDefaultUsername();
            }

            @Test
            @DisplayName("토큰의 스코프는 토큰 요청 정보에 저장된 스코프이어야 한다.")
            void shouldScopeIsStoredInRequest() {
                Set<OAuth2ScopeId> exceptedScopes = OAuth2TokenApplicationTestHelper.RAW_SCOPES.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

                OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);
                assertEquals(exceptedScopes, accessToken.getScopes());
            }
        }

    }

    private static abstract class AccessTokenGranterSetup {
        protected OAuth2ClientDetails clientDetails;
        protected OAuth2TokenRequest tokenRequest;

        protected ImplicitTokenGranter granter;

        @BeforeEach
        void setup() {
            OAuth2TokenApplicationTestHelper.MockTokenRequest mockTokenRequest = OAuth2TokenApplicationTestHelper.mockTokenRequest();

            configRequest(mockTokenRequest);

            this.clientDetails = OAuth2TokenApplicationTestHelper.mockClientDetails().configDefault().build();
            this.tokenRequest = mockTokenRequest.build();
            this.granter = new ImplicitTokenGranter(OAuth2TokenApplicationTestHelper.mockTokenIdGenerator(OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID), OAuth2TokenApplicationTestHelper.mockAccessTokenRepository().build());

            Clock clock = Clock.fixed(OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
            AbstractOAuth2TokenGranter.setClock(clock);
            configGranter(granter);
        }

        protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest request) {}
        protected void configGranter(ImplicitTokenGranter granter) {}

        @Test
        @DisplayName("토큰 아이디는 토큰 아이디 생성기에서 생성된 토큰 아이디어야 한다.")
        void shouldTokenIdIsCreatedByTokenIdGenerator() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            Assertions.assertEquals(OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID, accessToken.getTokenId());
        }

        @Test
        @DisplayName("토큰에 저장된 유저 아이디는 토큰 요청 정보에 저장된 유저 아이디 이어야 한다.")
        void shouldUsernameIsTokenRequestedUsername() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(USERNAME, accessToken.getUsername());
        }

        @Test
        @DisplayName("토큰의 클라이언트 아이디는 ClientDetails 에 저장된 클라이언트 아이디어야 한다.")
        void shouldClientIdIsStoredClientDetails() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(CLIENT_ID, accessToken.getClient());
        }

        @Test
        @DisplayName("토큰의 인증 타입은 Implicit 이어야 한다.")
        void shouldGrantTypeIsImplicit() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(AuthorizationGrantType.IMPLICIT, accessToken.getTokenGrantType());
        }

        @Test
        @DisplayName("토큰 발급 시간이 저장되어 있어야 한다.")
        void shouldSetTokenIssuedAt() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(TOKEN_CREATED_DATETIME, accessToken.getIssuedAt());
        }

        @Test
        @DisplayName("토큰의 유효시간이 설정되어 있어야 한다.")
        void shouldSetTokenValidity() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), accessToken.getExpiration());
        }
    }

}