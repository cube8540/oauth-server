package cube8540.oauth.authentication.oauth.security.endpoint;

import cube8540.oauth.authentication.oauth.AuthorizationResponseKey;
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.oauth.security.OAuth2AuthorizationCodeGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.web.servlet.ModelAndView;

import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.AUTHORIZATION_CODE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_AUTHORIZATION_CODE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.STATE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeAuthorizationCodeGenerator;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeAuthorizationRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("인가 코드 응답 메시지 추가 정보 입력 클래스 테스트")
class AuthorizationCodeResponseEnhancerTest {

    @Test
    @DisplayName("응답 타입이 AUTHORIZATION_CODE 가 아닐때")
    void responseTypeNotAuthorizationCode() {
        AuthorizationRequest request = makeAuthorizationRequest();
        OAuth2AuthorizationCodeGenerator generator = makeAuthorizationCodeGenerator(AUTHORIZATION_CODE);
        AuthorizationCodeResponseEnhancer enhancer = new AuthorizationCodeResponseEnhancer(generator);

        when(request.getResponseType()).thenReturn(OAuth2AuthorizationResponseType.TOKEN);

        ModelAndView modelAndView = mock(ModelAndView.class);
        enhancer.enhance(modelAndView, request);
        verify(generator, never()).generateNewAuthorizationCode(any());
    }

    @Test
    @DisplayName("응답 타입이 AUTHORIZATION_CODE 일때")
    void responseTypeAuthorizationCode() {
        AuthorizationRequest request = makeAuthorizationRequest();
        OAuth2AuthorizationCodeGenerator generator = makeAuthorizationCodeGenerator(AUTHORIZATION_CODE);
        AuthorizationCodeResponseEnhancer enhancer = new AuthorizationCodeResponseEnhancer(generator);

        when(request.getResponseType()).thenReturn(OAuth2AuthorizationResponseType.CODE);

        ModelAndView modelAndView = mock(ModelAndView.class);
        enhancer.enhance(modelAndView, request);
        verify(generator, times(1)).generateNewAuthorizationCode(request);
        verify(modelAndView, times(1)).addObject(AuthorizationResponseKey.CODE, RAW_AUTHORIZATION_CODE);
    }

    @Test
    @DisplayName("인가 요청 정보에 state 속성 없을때")
    void authorizationRequestNotHasStateAttribute() {
        AuthorizationRequest request = makeAuthorizationRequest();
        OAuth2AuthorizationCodeGenerator generator = makeAuthorizationCodeGenerator(AUTHORIZATION_CODE);
        AuthorizationCodeResponseEnhancer enhancer = new AuthorizationCodeResponseEnhancer(generator);

        when(request.getResponseType()).thenReturn(OAuth2AuthorizationResponseType.CODE);
        when(request.getState()).thenReturn(null);

        ModelAndView modelAndView = mock(ModelAndView.class);
        enhancer.enhance(modelAndView, request);
        verify(modelAndView, never()).addObject(eq(AuthorizationResponseKey.STATE), anyString());
        verify(modelAndView, never()).addObject(AuthorizationResponseKey.STATE, null);
    }

    @Test
    @DisplayName("인가 요청 정보에 state 속성이 있을떄")
    void authorizationRequestHasStateAttribute() {
        AuthorizationRequest request = makeAuthorizationRequest();
        OAuth2AuthorizationCodeGenerator generator = makeAuthorizationCodeGenerator(AUTHORIZATION_CODE);
        AuthorizationCodeResponseEnhancer enhancer = new AuthorizationCodeResponseEnhancer(generator);

        when(request.getResponseType()).thenReturn(OAuth2AuthorizationResponseType.CODE);
        when(request.getState()).thenReturn(STATE);

        ModelAndView modelAndView = mock(ModelAndView.class);
        enhancer.enhance(modelAndView, request);
        verify(modelAndView, times(1)).addObject(AuthorizationResponseKey.STATE, STATE);
    }

    @Test
    @DisplayName("다음 추가 입력 정보 클래스가 없을때")
    void notHasNextEnhancer() {
        AuthorizationRequest request = makeAuthorizationRequest();
        OAuth2AuthorizationCodeGenerator generator = makeAuthorizationCodeGenerator(AUTHORIZATION_CODE);
        AuthorizationCodeResponseEnhancer enhancer = new AuthorizationCodeResponseEnhancer(generator);

        ModelAndView modelAndView = mock(ModelAndView.class);
        assertEquals(modelAndView, enhancer.enhance(modelAndView, request));
    }

    @Test
    @DisplayName("다음 추가 입력 정보 클래스가 있을때")
    void hasNextEnhancer() {
        ModelAndView modelAndView = mock(ModelAndView.class);
        AuthorizationRequest request = makeAuthorizationRequest();
        OAuth2AuthorizationCodeGenerator generator = makeAuthorizationCodeGenerator(AUTHORIZATION_CODE);
        AuthorizationCodeResponseEnhancer enhancer = new AuthorizationCodeResponseEnhancer(generator);

        AuthorizationCodeResponseEnhancer nextEnhancer = mock(AuthorizationCodeResponseEnhancer.class);
        ModelAndView nextModelAndView = mock(ModelAndView.class);
        when(nextEnhancer.enhance(modelAndView, request)).thenReturn(nextModelAndView);
        enhancer.setNext(nextEnhancer);

        assertEquals(nextModelAndView, enhancer.enhance(modelAndView, request));
    }
}