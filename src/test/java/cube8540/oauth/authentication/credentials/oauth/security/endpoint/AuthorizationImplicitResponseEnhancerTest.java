package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.EXPIRATION_IN;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_RESOLVED_REDIRECT_URI;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_RESOLVED_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.SCOPE;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.STATE;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.TOKEN_TYPE;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.mockAccessTokenGranter;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.mockClientDetails;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@DisplayName("암묵적 동의 방식 응답 메시지 추가 정보 입력 클래스 테스트")
class AuthorizationImplicitResponseEnhancerTest {

    @Nested
    @DisplayName("ModelAndView 추가 정보 설정")
    class EnhanceModelAndView {

        @Nested
        @DisplayName("응답 타입이 토큰이 아닐시")
        class WhenResponseTypeIsNotToken extends AssertSetup {
            private AuthorizationRequest request;

            @BeforeEach
            void setupRequest() {
                this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest()
                        .configDefault()
                        .configResponseType(OAuth2AuthorizationResponseType.CODE)
                        .build();
            }

            @Test
            @DisplayName("토큰을 할당 하지 않아야 한다.")
            void shouldNotGrantToken() {
                enhancer.enhance(modelAndView, request);

                verifyNoMoreInteractions(granter);
            }
        }

        @Nested
        @DisplayName("응답 타입이 토큰 일시")
        class WhenResponseTypeIsToken extends AssertSetup {
            private AuthorizationRequest request;
            private OAuth2ClientDetails clientDetails;

            private RedirectView view;

            @BeforeEach
            void setupRequest() {
                this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest()
                        .configDefault()
                        .configResponseType(OAuth2AuthorizationResponseType.TOKEN)
                        .build();
            }

            @Override
            protected void configAccessTokenGranter(AuthorizationEndpointTestHelper.MockOAuth2AccessTokenGranter granter) {
                OAuth2AccessTokenDetails accessToken = AuthorizationEndpointTestHelper.mockAccessToken().configDefault().build();
                granter.configToken(accessToken);
            }

            @Override
            protected void configClientDetailsService(AuthorizationEndpointTestHelper.MockClientDetailsService clientDetailsService) {
                this.clientDetails = mockClientDetails().configDefault().build();
                clientDetailsService.registerClient(clientDetails);
            }

            @Override
            protected void configModelAndView(ModelAndView modelAndView) {
                this.view = new RedirectView(RAW_RESOLVED_REDIRECT_URI);
                when(modelAndView.getView()).thenReturn(view);
            }

            @Test
            @DisplayName("인가 요청에 있는 클라이언트 정보로 토큰을 부여 해야 한다.")
            void shouldGrantTokenByAuthorizationRequestClient() {
                ArgumentCaptor<OAuth2ClientDetails> clientCaptor = ArgumentCaptor.forClass(OAuth2ClientDetails.class);
                enhancer.enhance(modelAndView, request);

                verify(granter, times(1)).grant(clientCaptor.capture(), any());
                assertEquals(clientDetails, clientCaptor.getValue());
            }

            @Test
            @DisplayName("인가 요청에 있는 유저 아이디로 토큰을 부여 해야 한다.")
            void shouldGrantTokenByAuthorizationRequestUsername() {
                ArgumentCaptor<OAuth2TokenRequest> tokenRequestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);
                enhancer.enhance(modelAndView, request);

                verify(granter, times(1)).grant(any(), tokenRequestCaptor.capture());
                assertEquals(RAW_USERNAME, tokenRequestCaptor.getValue().getUsername());
            }

            @Test
            @DisplayName("토큰 부여시 부여 타입은 Implicit 이어야 한다.")
            void shouldGrantTypeIsImplicit() {
                ArgumentCaptor<OAuth2TokenRequest> tokenRequestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);
                enhancer.enhance(modelAndView, request);

                verify(granter, times(1)).grant(any(), tokenRequestCaptor.capture());
                assertEquals(AuthorizationGrantType.IMPLICIT, tokenRequestCaptor.getValue().getGrantType());
            }

            @Test
            @DisplayName("토큰 부여시 스코프는 인가 요청에서 요청한 스코프여야 한다.")
            void shouldGrantScopesInAuthorizationRequest() {
                ArgumentCaptor<OAuth2TokenRequest> tokenRequestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);
                enhancer.enhance(modelAndView, request);

                verify(granter, times(1)).grant(any(), tokenRequestCaptor.capture());
                assertEquals(SCOPE, tokenRequestCaptor.getValue().getScopes());
            }

            @Test
            @DisplayName("리다이렉트 URL에 토큰의 정보를 적어야 한다.")
            void shouldSetTokenInformationInRedirectUrl() {
                enhancer.enhance(modelAndView, request);

                String tokenInfo = RAW_RESOLVED_REDIRECT_URI + "#access_token=" + RAW_ACCESS_TOKEN_ID + "&token_type=" + TOKEN_TYPE
                        + "&expires_in=" + EXPIRATION_IN + "&scope=" + String.join(" ", RAW_RESOLVED_SCOPES);
                assertEquals(tokenInfo, view.getUrl());
            }

            @Nested
            @DisplayName("입력 받은 인가 요청 정보에 state 정보가 있을시")
            class WhenAuthorizationRequestHasState extends AssertSetup {
                private AuthorizationRequest request;

                private RedirectView view;

                @BeforeEach
                void setupRequest() {
                    this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest()
                            .configDefault()
                            .configResponseType(OAuth2AuthorizationResponseType.TOKEN)
                            .configState()
                            .build();
                }

                @Override
                protected void configAccessTokenGranter(AuthorizationEndpointTestHelper.MockOAuth2AccessTokenGranter granter) {
                    granter.configToken(AuthorizationEndpointTestHelper.mockAccessToken().configDefault().build());
                }

                @Override
                protected void configClientDetailsService(AuthorizationEndpointTestHelper.MockClientDetailsService clientDetailsService) {
                    clientDetailsService.registerClient(mockClientDetails().configDefault().build());
                }

                @Override
                protected void configModelAndView(ModelAndView modelAndView) {
                    this.view = new RedirectView(RAW_RESOLVED_REDIRECT_URI);
                    when(modelAndView.getView()).thenReturn(view);
                }

                @Test
                @DisplayName("ModelAndView 에 state 정보를 저장 해야 한다.")
                void shouldSaveStateInModelAndView() {
                    enhancer.enhance(modelAndView, request);

                    String tokenInfo = RAW_RESOLVED_REDIRECT_URI + "#access_token=" + RAW_ACCESS_TOKEN_ID + "&token_type=" + TOKEN_TYPE
                            + "&expires_in=" + EXPIRATION_IN + "&scope=" + String.join(" ", RAW_RESOLVED_SCOPES)
                            + "&state=" + STATE;
                    assertEquals(tokenInfo, view.getUrl());
                }

            }
        }

        @Nested
        @DisplayName("다음 추가 입력 정보 클래스가 있을시")
        class WhenHasNextEnhancer extends AssertSetup {

            private AuthorizationRequest request;

            private ModelAndView nextModelAndView;
            private AuthorizationResponseEnhancer nextEnhancer;

            @BeforeEach
            void setupRequest() {
                this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest().configResponseType(OAuth2AuthorizationResponseType.CODE).configDefault().build();
            }

            @Override
            protected void configEnhancer(AuthorizationImplicitResponseEnhancer handler) {
                this.nextEnhancer = mock(AuthorizationResponseEnhancer.class);
                this.nextModelAndView = mock(ModelAndView.class);

                when(nextEnhancer.enhance(any(), any())).thenReturn(nextModelAndView);
                handler.setNext(nextEnhancer);
            }

            @Test
            @DisplayName("다음 추가 입력 클래스에서 반환된 ModelAndView 를 반환 해야 한다.")
            void shouldReturnNextEnhancerModelAndView() {
                ModelAndView mv = enhancer.enhance(modelAndView, request);
                assertEquals(nextModelAndView, mv);
            }
        }

        @Nested
        @DisplayName("다음 추가 입력 정보 클래스가 없을시")
        class WhenHasNotNextEnhancer extends AssertSetup {

            private AuthorizationRequest request;

            @BeforeEach
            void setupRequest() {
                this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest().configResponseType(OAuth2AuthorizationResponseType.CODE).configDefault().build();
            }

            @Test
            @DisplayName("입력 받은 ModelAndView 를 반환 해야 한다.")
            void shouldReturnsInputModelAndView() {
                ModelAndView mv = enhancer.enhance(modelAndView, request);
                assertEquals(modelAndView, mv);
            }
        }
    }

    private static abstract class AssertSetup {
        protected OAuth2AccessTokenGranter granter;
        protected OAuth2ClientDetailsService clientDetailsService;
        protected AuthorizationImplicitResponseEnhancer enhancer;

        protected ModelAndView modelAndView;
        protected AuthorizationRequest request;

        @BeforeEach
        void setup() {
            AuthorizationEndpointTestHelper.MockOAuth2AccessTokenGranter mockTokenGranter = mockAccessTokenGranter();
            AuthorizationEndpointTestHelper.MockClientDetailsService mockClientDetailsService = AuthorizationEndpointTestHelper.mockClientDetailsService();

            this.modelAndView = mock(ModelAndView.class);

            configAccessTokenGranter(mockTokenGranter);
            configClientDetailsService(mockClientDetailsService);

            this.granter = mockTokenGranter.build();
            this.clientDetailsService = mockClientDetailsService.build();
            this.enhancer = new AuthorizationImplicitResponseEnhancer(granter, clientDetailsService);

            configEnhancer(this.enhancer);
            configModelAndView(modelAndView);
        }

        protected void configAccessTokenGranter(AuthorizationEndpointTestHelper.MockOAuth2AccessTokenGranter granter) {}
        protected void configClientDetailsService(AuthorizationEndpointTestHelper.MockClientDetailsService clientDetailsService) {}
        protected void configModelAndView(ModelAndView modelAndView) {}
        protected void configEnhancer(AuthorizationImplicitResponseEnhancer handler) {}
    }
}