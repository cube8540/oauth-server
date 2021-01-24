package cube8540.oauth.authentication.oauth.security.endpoint;

import cube8540.oauth.authentication.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.EXPIRATION_IN;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_RESOLVED_REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_RESOLVED_SCOPES;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.SCOPE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.STATE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.TOKEN_TYPE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeAccessToken;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeAuthorizationRequest;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeClientDetailsService;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeTokenGranter;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@DisplayName("암묵적 동의 방식 응답 메시지 추가 정보 입력 클래스 테스트")
class AuthorizationImplicitResponseEnhancerTest {

    @Test
    @DisplayName("응답 타입이 TOKEN 이 아닐때")
    void responseTypeNotToken() {
        OAuth2AccessTokenGranter granter = makeTokenGranter(makeAccessToken());
        OAuth2ClientDetailsService clientDetailsService = makeClientDetailsService(makeClientDetails());
        AuthorizationRequest request = makeAuthorizationRequest();
        AuthorizationImplicitResponseEnhancer enhancer = new AuthorizationImplicitResponseEnhancer(granter, clientDetailsService);

        when(request.getResponseType()).thenReturn(OAuth2AuthorizationResponseType.CODE);

        ModelAndView modelAndView = mock(ModelAndView.class);
        enhancer.enhance(modelAndView, request);
        verifyNoMoreInteractions(granter);
    }

    @Test
    @DisplayName("응답 타입이 TOKEN 이며 요청 정보에 state 속성이 없을때")
    void whenResponseTypeTokenAndAuthorizationRequestNotHasStateAttribute() {
        ArgumentCaptor<OAuth2ClientDetails> clientCaptor = ArgumentCaptor.forClass(OAuth2ClientDetails.class);
        ArgumentCaptor<OAuth2TokenRequest> tokenRequestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);
        String tokenInfo = RAW_RESOLVED_REDIRECT_URI + "#access_token=" + RAW_ACCESS_TOKEN_ID + "&token_type=" + TOKEN_TYPE
                + "&expires_in=" + EXPIRATION_IN + "&scope=" + String.join(" ", RAW_RESOLVED_SCOPES);
        ModelAndView modelAndView = mock(ModelAndView.class);
        RedirectView redirectView = new RedirectView(RAW_RESOLVED_REDIRECT_URI);
        OAuth2AccessTokenGranter granter = makeTokenGranter(makeAccessToken());
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2ClientDetailsService clientDetailsService = makeClientDetailsService(clientDetails);
        AuthorizationRequest request = makeAuthorizationRequest();
        AuthorizationImplicitResponseEnhancer enhancer = new AuthorizationImplicitResponseEnhancer(granter, clientDetailsService);

        when(modelAndView.getView()).thenReturn(redirectView);
        when(request.getState()).thenReturn(null);
        when(request.getResponseType()).thenReturn(OAuth2AuthorizationResponseType.TOKEN);

        enhancer.enhance(modelAndView, request);
        verify(granter, times(1)).grant(clientCaptor.capture(), tokenRequestCaptor.capture());
        assertEquals(clientDetails, clientCaptor.getValue());
        assertEquals(RAW_USERNAME, tokenRequestCaptor.getValue().getUsername());
        assertEquals(AuthorizationGrantType.IMPLICIT, tokenRequestCaptor.getValue().getGrantType());
        assertEquals(SCOPE, tokenRequestCaptor.getValue().getScopes());
        assertEquals(tokenInfo, redirectView.getUrl());
    }

    @Test
    @DisplayName("응답 타입이 TOKEN 이며 요청 정보에 state 속성이 있을때")
    void whenResponseTypeTokenAndAuthorizationRequestHasStateAttribute() {
        ArgumentCaptor<OAuth2ClientDetails> clientCaptor = ArgumentCaptor.forClass(OAuth2ClientDetails.class);
        ArgumentCaptor<OAuth2TokenRequest> tokenRequestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);
        String tokenInfo = RAW_RESOLVED_REDIRECT_URI + "#access_token=" + RAW_ACCESS_TOKEN_ID + "&token_type=" + TOKEN_TYPE
                + "&expires_in=" + EXPIRATION_IN + "&scope=" + String.join(" ", RAW_RESOLVED_SCOPES) + "&state=" + STATE;
        ModelAndView modelAndView = mock(ModelAndView.class);
        RedirectView redirectView = new RedirectView(RAW_RESOLVED_REDIRECT_URI);
        OAuth2AccessTokenGranter granter = makeTokenGranter(makeAccessToken());
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2ClientDetailsService clientDetailsService = makeClientDetailsService(clientDetails);
        AuthorizationRequest request = makeAuthorizationRequest();
        AuthorizationImplicitResponseEnhancer enhancer = new AuthorizationImplicitResponseEnhancer(granter, clientDetailsService);

        when(modelAndView.getView()).thenReturn(redirectView);
        when(request.getState()).thenReturn(STATE);
        when(request.getResponseType()).thenReturn(OAuth2AuthorizationResponseType.TOKEN);

        enhancer.enhance(modelAndView, request);
        verify(granter, times(1)).grant(clientCaptor.capture(), tokenRequestCaptor.capture());
        assertEquals(clientDetails, clientCaptor.getValue());
        assertEquals(RAW_USERNAME, tokenRequestCaptor.getValue().getUsername());
        assertEquals(AuthorizationGrantType.IMPLICIT, tokenRequestCaptor.getValue().getGrantType());
        assertEquals(SCOPE, tokenRequestCaptor.getValue().getScopes());
        assertEquals(tokenInfo, redirectView.getUrl());
    }

    @Test
    @DisplayName("다음 추가 입력 정보 클래스가 없을때")
    void notHasNextEnhancer() {
        AuthorizationRequest request = makeAuthorizationRequest();
        OAuth2AccessTokenGranter granter = makeTokenGranter(makeAccessToken());
        OAuth2ClientDetailsService clientDetailsService = makeClientDetailsService(makeClientDetails());
        AuthorizationImplicitResponseEnhancer enhancer = new AuthorizationImplicitResponseEnhancer(granter, clientDetailsService);

        ModelAndView modelAndView = mock(ModelAndView.class);
        assertEquals(modelAndView, enhancer.enhance(modelAndView, request));
    }

    @Test
    @DisplayName("다음 추가 입력 정보 클래스가 있을때")
    void hasNextEnhancer() {
        ModelAndView modelAndView = mock(ModelAndView.class);
        AuthorizationRequest request = makeAuthorizationRequest();
        OAuth2AccessTokenGranter granter = makeTokenGranter(makeAccessToken());
        OAuth2ClientDetailsService clientDetailsService = makeClientDetailsService(makeClientDetails());
        AuthorizationImplicitResponseEnhancer enhancer = new AuthorizationImplicitResponseEnhancer(granter, clientDetailsService);

        AuthorizationImplicitResponseEnhancer nextEnhancer = mock(AuthorizationImplicitResponseEnhancer.class);
        ModelAndView nextModelAndView = mock(ModelAndView.class);
        when(nextEnhancer.enhance(modelAndView, request)).thenReturn(nextModelAndView);
        enhancer.setNext(nextEnhancer);

        assertEquals(nextModelAndView, enhancer.enhance(modelAndView, request));
    }
}