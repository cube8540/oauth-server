package cube8540.oauth.authentication.oauth.security.endpoint;

import cube8540.oauth.authentication.oauth.AuthorizationRequestKey;
import cube8540.oauth.authentication.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.oauth.error.OAuth2ClientRegistrationException;
import cube8540.oauth.authentication.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.oauth.security.AutoApprovalScopeHandler;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.bind.support.SessionAttributeStore;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;

import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.APPROVAL_SCOPES;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.CLIENT_NAME;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.CLIENT_SCOPE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.FORWARD_PAGE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.INVALID_GRANT_ERROR;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.INVALID_GRANT_RESPONSE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.INVALID_REQUEST_ERROR;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.INVALID_REQUEST_RESPONSE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_RESOLVED_REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_RESOLVED_SCOPES;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.REQUIRED_APPROVAL_SCOPES;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.REQUIRED_APPROVAL_SCOPE_DETAILS;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.REQUIRE_APPROVAL_CLIENT_SCOPES;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.RESOLVED_REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.SCOPE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.STATE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.UNAUTHORIZED_CLIENT_ERROR;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.UNAUTHORIZED_CLIENT_RESPONSE;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeAllApprovalScopeHandler;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeAuthenticationTypeNotAuthentication;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeAuthorityDetailsService;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeAuthorizationRequest;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeAuthorizedAuthentication;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeAutoApprovalScopeHandler;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeClientDetailsService;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeEmptyApprovalParameter;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeEmptyClientDetailsService;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeEmptyModel;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeErrorRequestValidator;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeExceptionTranslator;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeHttpServletRequest;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeMismatchRedirectResolver;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeModel;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeNotAuthorizedAuthentication;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makePassRequestValidator;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeRedirectResolver;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeRequestParameter;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeResponseEnhancer;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeScopeApprovalResolver;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeServletWebRequest;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeSessionAttributeStore;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.makeSessionStatus;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.plus;
import static cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpointTestHelper.subtract;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("인가 엔드 포인트 테스트")
class AuthorizationEndpointTest {

    @Test
    @DisplayName("인증 정보가 Authentication 타입이 아닐때 인가 요청")
    void requestAuthorizationWhenPrincipalTypeIsNotAuthentication() {
        Principal principal = makeAuthenticationTypeNotAuthentication();
        Map<String, Object> model = makeEmptyModel();
        Map<String, String> parameter = makeRequestParameter();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        assertThrows(InsufficientAuthenticationException.class, () -> endpoint.authorize(parameter, model, principal));
    }

    @Test
    @DisplayName("인증 받지 않은 요청 일때 인가 요청")
    void requestAuthorizationWhenNotAuthenticationRequest() {
        Principal principal = makeNotAuthorizedAuthentication();
        Map<String, Object> model = makeEmptyModel();
        Map<String, String> parameter = makeRequestParameter();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        assertThrows(InsufficientAuthenticationException.class, () -> endpoint.authorize(parameter, model, principal));
    }

    @Test
    @DisplayName("요청 받은 응답 타입이 null 일때 인가 요청")
    void requestAuthorizationWhenResponseTypeIsNull() {
        Principal principal = makeAuthorizedAuthentication();
        Map<String, Object> model = makeEmptyModel();
        Map<String, String> parameter = makeRequestParameter();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        parameter.put(AuthorizationRequestKey.RESPONSE_TYPE, null);

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.authorize(parameter, model, principal)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("요청 받은 클라이언트 아이디가 null 일때 인가 요청")
    void requestAuthorizationWhenClientIdIsNull() {
        Principal principal = makeAuthorizedAuthentication();
        Map<String, Object> model = makeEmptyModel();
        Map<String, String> parameter = makeRequestParameter();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        parameter.put(AuthorizationRequestKey.CLIENT_ID, null);

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.authorize(parameter, model, principal)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("요청한 스코프가 유효 하지 않을때 인가 요청")
    void requestAuthorizationWhenRequestScopeNotAllowed() {
        Principal principal = makeAuthorizedAuthentication();
        Map<String, Object> model = makeEmptyModel();
        Map<String, String> parameter = makeRequestParameter();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator errorValidator = makeErrorRequestValidator(clientDetails, SCOPE);
        RedirectResolver redirectResolver = makeRedirectResolver(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setRequestValidator(errorValidator);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> endpoint.authorize(parameter, model, principal)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
    }

    @Test
    @DisplayName("요청한 스코프가 null 일때 인가 요청")
    void requestAuthorizationWhenRequestScopeIsNull() {
        Principal principal = makeAuthorizedAuthentication();
        Map<String, Object> model = makeEmptyModel();
        Map<String, String> parameter = makeRequestParameter();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator passValidator = makePassRequestValidator(clientDetails, Collections.emptySet());
        RedirectResolver redirectResolver = makeRedirectResolver(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, CLIENT_SCOPE, REQUIRE_APPROVAL_CLIENT_SCOPES));

        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setRequestValidator(passValidator);
        endpoint.setApprovalPage(FORWARD_PAGE);
        parameter.put(AuthorizationRequestKey.SCOPE, null);

        ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);
        AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
        assertStoredRequest(model, parameter, modelAndView, storedRequest);
        assertEquals(CLIENT_SCOPE, storedRequest.getRequestScopes());
        assertEquals(REQUIRED_APPROVAL_SCOPE_DETAILS, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_SCOPES_NAME));
        assertEquals(subtract(CLIENT_SCOPE, REQUIRE_APPROVAL_CLIENT_SCOPES), model.get(AuthorizationEndpoint.AUTHORIZATION_AUTO_APPROVAL_SCOPES_NAME));
    }

    @Test
    @DisplayName("요청한 스코프가 nul 이며 모든 스코프가 자동 승인일시")
    void requestAuthorizationWhenRequestScopeIsNullAndScopeAllAutoApproval() {
        ArgumentCaptor<ModelAndView> viewCaptor = ArgumentCaptor.forClass(ModelAndView.class);
        ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        Principal principal = makeAuthorizedAuthentication();
        Map<String, Object> model = makeEmptyModel();
        Map<String, String> parameter = makeRequestParameter();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator passValidator = makePassRequestValidator(clientDetails, Collections.emptySet());
        RedirectResolver redirectResolver = makeRedirectResolver(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI);
        AuthorizationResponseEnhancer responseEnhancer = makeResponseEnhancer();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                responseEnhancer,
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setRequestValidator(passValidator);
        endpoint.setApprovalPage(FORWARD_PAGE);
        parameter.put(AuthorizationRequestKey.SCOPE, null);

        ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);
        assertEquals(makeEmptyModel(), model);
        assertTrue(modelAndView.getView() instanceof RedirectView);
        assertEquals(RESOLVED_REDIRECT_URI.toString(), ((RedirectView) modelAndView.getView()).getUrl());
        verify(responseEnhancer, times(1)).enhance(viewCaptor.capture(), requestCaptor.capture());
        assertEquals(modelAndView, viewCaptor.getValue());
        assertEquals(CLIENT_SCOPE, requestCaptor.getValue().getRequestScopes());
    }

    @Test
    @DisplayName("요청 스코프가 유효할 때 인가 요청")
    void requestAuthorizationWhenRequestScopeAllowed() {
        Principal principal = makeAuthorizedAuthentication();
        Map<String, Object> model = makeEmptyModel();
        Map<String, String> parameter = makeRequestParameter();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator passValidator = makePassRequestValidator(clientDetails, SCOPE);
        RedirectResolver redirectResolver = makeRedirectResolver(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setRequestValidator(passValidator);
        endpoint.setApprovalPage(FORWARD_PAGE);

        ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);
        AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
        assertStoredRequest(model, parameter, modelAndView, storedRequest);
        assertEquals(SCOPE, storedRequest.getRequestScopes());
        assertEquals(REQUIRED_APPROVAL_SCOPE_DETAILS, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_SCOPES_NAME));
        assertEquals(subtract(SCOPE, REQUIRED_APPROVAL_SCOPES), model.get(AuthorizationEndpoint.AUTHORIZATION_AUTO_APPROVAL_SCOPES_NAME));
    }

    @Test
    @DisplayName("모든 스코프가 자동 승인 일시")
    void requestAuthorizationWhenScopeAllAutoApproval() {
        ArgumentCaptor<ModelAndView> viewCaptor = ArgumentCaptor.forClass(ModelAndView.class);
        ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        Principal principal = makeAuthorizedAuthentication();
        Map<String, Object> model = makeEmptyModel();
        Map<String, String> parameter = makeRequestParameter();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator passValidator = makePassRequestValidator(clientDetails, SCOPE);
        RedirectResolver redirectResolver = makeRedirectResolver(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI);
        AuthorizationResponseEnhancer responseEnhancer = makeResponseEnhancer();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                responseEnhancer,
                makeAllApprovalScopeHandler(principal, clientDetails, SCOPE));

        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setRequestValidator(passValidator);
        endpoint.setApprovalPage(FORWARD_PAGE);

        ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);
        assertEquals(makeEmptyModel(), model);
        assertTrue(modelAndView.getView() instanceof RedirectView);
        assertEquals(RESOLVED_REDIRECT_URI.toString(), ((RedirectView) modelAndView.getView()).getUrl());
        verify(responseEnhancer, times(1)).enhance(viewCaptor.capture(), requestCaptor.capture());
        assertEquals(modelAndView, viewCaptor.getValue());
        assertEquals(SCOPE, requestCaptor.getValue().getRequestScopes());
    }

    @Test
    @DisplayName("인증 정보가 Authentication 타입이 아닐때 스코프 허용")
    void approvalScopeWhenPrincipalTypeIsNotAuthentication() {
        Principal principal = makeNotAuthorizedAuthentication();
        Map<String, String> approvalParameter = makeEmptyApprovalParameter();
        Map<String, Object> model = makeEmptyModel();
        SessionStatus sessionStatus = makeSessionStatus();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        assertThrows(InsufficientAuthenticationException.class, () -> endpoint.approval(approvalParameter, model, sessionStatus, principal));
    }

    @Test
    @DisplayName("인증을 받지 않은 요청일 때 스코프 허용")
    void approvalScopeWhenRequestNotAuthentication() {
        Principal principal = makeNotAuthorizedAuthentication();
        Map<String, String> approvalParameter = makeEmptyApprovalParameter();
        Map<String, Object> model = makeEmptyModel();
        SessionStatus sessionStatus = makeSessionStatus();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        assertThrows(InsufficientAuthenticationException.class, () -> endpoint.approval(approvalParameter, model, sessionStatus, principal));
    }

    @Test
    @DisplayName("세션에 원본 인가 요청 정보가 없을떄 스코프 허용")
    void approvalScopeWhenSessionNotHasOriginalAuthorizationRequest() {
        Principal principal = makeAuthorizedAuthentication();
        Map<String, String> approvalParameter = makeEmptyApprovalParameter();
        Map<String, Object> model = makeModel(null, makeAuthorizationRequest(), Collections.emptySet());
        SessionStatus sessionStatus = makeSessionStatus();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(makeClientDetailsService(RAW_CLIENT_ID, clientDetails), makeAuthorityDetailsService(), makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.approval(approvalParameter, model, sessionStatus, principal)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("세션에 인가 요청 정보가 없을때 스코프 허용")
    void approvalScopeWhenSessionNotHasAuthorizationRequest() {
        Principal principal = makeAuthorizedAuthentication();
        Map<String, String> approvalParameter = makeEmptyApprovalParameter();
        Map<String, Object> model = makeModel(makeRequestParameter(), null, Collections.emptySet());
        SessionStatus sessionStatus = makeSessionStatus();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(makeClientDetailsService(RAW_CLIENT_ID, clientDetails), makeAuthorityDetailsService(), makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.approval(approvalParameter, model, sessionStatus, principal)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("세션에 자동 허가 스코프 접오가 없을때 스코프 허용")
    void approvalScopeWhenAutoApprovalScopeIsNull() {
        Principal principal = makeAuthorizedAuthentication();
        Map<String, String> approvalParameter = makeEmptyApprovalParameter();
        Map<String, Object> model = makeModel(makeRequestParameter(), makeAuthorizationRequest(), null);
        SessionStatus sessionStatus = makeSessionStatus();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(makeClientDetailsService(RAW_CLIENT_ID, clientDetails), makeAuthorityDetailsService(), makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES));

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.approval(approvalParameter, model, sessionStatus, principal)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("자동 허용 스코프가 비어 있을떄 스코프 허용")
    void approvalScopeWhenAutoApprovalScopeIsEmpty() {
        ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        ArgumentCaptor<ModelAndView> viewCaptor = ArgumentCaptor.forClass(ModelAndView.class);
        Principal principal = makeAuthorizedAuthentication();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        Map<String, String> approvalParameter = makeEmptyApprovalParameter();
        Map<String, String> originalAuthorizationRequestMap = makeRequestParameter();
        AuthorizationRequest originalAuthorizationRequest = makeAuthorizationRequest();
        Map<String, Object> model = makeModel(originalAuthorizationRequestMap, originalAuthorizationRequest, Collections.emptySet());
        AuthorizationResponseEnhancer enhancer = makeResponseEnhancer();
        SessionStatus sessionStatus = makeSessionStatus();
        ScopeApprovalResolver resolver = makeScopeApprovalResolver(originalAuthorizationRequest, approvalParameter, RAW_RESOLVED_SCOPES);
        AutoApprovalScopeHandler autoApprovalScopeHandler = makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails), makeAuthorityDetailsService(), enhancer, autoApprovalScopeHandler);

        endpoint.setApprovalResolver(resolver);

        ModelAndView modelAndView = endpoint.approval(approvalParameter, model, sessionStatus, principal);
        verify(autoApprovalScopeHandler, times(1)).storeAutoApprovalScopes(principal, clientDetails, RAW_RESOLVED_SCOPES);
        verify(originalAuthorizationRequest, never()).setRequestScopes(any());
        verify(originalAuthorizationRequest, never()).setRedirectUri(any());
        assertTrue(modelAndView.getView() instanceof RedirectView);
        assertEquals(RESOLVED_REDIRECT_URI.toString(), ((RedirectView) modelAndView.getView()).getUrl());
        verify(enhancer, times(1)).enhance(viewCaptor.capture(), requestCaptor.capture());
        assertEquals(modelAndView, viewCaptor.getValue());
        assertEquals(RAW_RESOLVED_SCOPES, requestCaptor.getValue().getRequestScopes());
    }

    @Test
    @DisplayName("자동 허용 스코프가 비어 있지 않을때 스코프 허용")
    void approvalScopeWhenAutoApprovalScopeIsNotEmpty() {
        ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);
        ArgumentCaptor<ModelAndView> viewCaptor = ArgumentCaptor.forClass(ModelAndView.class);
        Principal principal = makeAuthorizedAuthentication();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        Map<String, String> approvalParameter = makeEmptyApprovalParameter();
        Map<String, String> originalAuthorizationRequestMap = makeRequestParameter();
        AuthorizationRequest originalAuthorizationRequest = makeAuthorizationRequest();
        Map<String, Object> model = makeModel(originalAuthorizationRequestMap, originalAuthorizationRequest, APPROVAL_SCOPES);
        AuthorizationResponseEnhancer enhancer = makeResponseEnhancer();
        SessionStatus sessionStatus = makeSessionStatus();
        ScopeApprovalResolver resolver = makeScopeApprovalResolver(originalAuthorizationRequest, approvalParameter, RAW_RESOLVED_SCOPES);
        AutoApprovalScopeHandler autoApprovalScopeHandler = makeAutoApprovalScopeHandler(principal, clientDetails, SCOPE, REQUIRED_APPROVAL_SCOPES);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails), makeAuthorityDetailsService(), enhancer, autoApprovalScopeHandler);

        endpoint.setApprovalResolver(resolver);

        ModelAndView modelAndView = endpoint.approval(approvalParameter, model, sessionStatus, principal);
        verify(autoApprovalScopeHandler, times(1)).storeAutoApprovalScopes(principal, clientDetails, plus(RAW_RESOLVED_SCOPES, APPROVAL_SCOPES));
        verify(originalAuthorizationRequest, never()).setRequestScopes(any());
        verify(originalAuthorizationRequest, never()).setRedirectUri(any());
        assertTrue(modelAndView.getView() instanceof RedirectView);
        assertEquals(RESOLVED_REDIRECT_URI.toString(), ((RedirectView) modelAndView.getView()).getUrl());
        verify(enhancer, times(1)).enhance(viewCaptor.capture(), requestCaptor.capture());
        assertEquals(modelAndView, viewCaptor.getValue());
        assertEquals(plus(RAW_RESOLVED_SCOPES, APPROVAL_SCOPES), requestCaptor.getValue().getRequestScopes());
    }

    @Test
    @DisplayName("리다이렉트 인증 예외 발생시")
    void whenThrowsRedirectMismatchException() {
        RedirectMismatchException exception = new RedirectMismatchException("TEST");
        ServletWebRequest webRequest = makeServletWebRequest();
        OAuth2ExceptionTranslator translator = makeExceptionTranslator(exception, INVALID_GRANT_RESPONSE);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(makeClientDetailsService(RAW_CLIENT_ID, makeClientDetails()), makeAuthorityDetailsService(), makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(makeAuthorizedAuthentication(), makeClientDetails(), SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setExceptionTranslator(translator);

        ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(exception, webRequest);
        verify(webRequest.getResponse(), times(1)).setStatus(401);
        assertEquals("/oauth/error", modelAndView.getViewName());
        assertEquals(INVALID_GRANT_ERROR, modelAndView.getModel().get("error"));
    }

    @Test
    @DisplayName("OAuth2 클라이언트 인증 예외 발생시")
    void whenThrowsClientAuthenticationException() {
        OAuth2ClientRegistrationException exception = new OAuth2ClientRegistrationException("TEST");
        ServletWebRequest webRequest = makeServletWebRequest();
        OAuth2ExceptionTranslator translator = makeExceptionTranslator(exception, UNAUTHORIZED_CLIENT_RESPONSE);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, makeClientDetails()),
                makeAuthorityDetailsService(), makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(makeAuthorizedAuthentication(), makeClientDetails(), SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setExceptionTranslator(translator);

        ModelAndView modelAndView = endpoint.handleClientRegistrationException(exception, webRequest);
        verify(webRequest.getResponse(), times(1)).setStatus(401);
        assertEquals("/oauth/error", modelAndView.getViewName());
        assertEquals(UNAUTHORIZED_CLIENT_ERROR, modelAndView.getModel().get("error"));
    }

    @Test
    @DisplayName("세션에 인가 요청에 대한 정보가 있지 않으며 예외 처리 도중 클라이언트 정보 검색 예외가 발생 했을때")
    void whenSessionNotHasAuthorizationRequestAndThrowsClientRegistrationExceptionDuringExceptionHandling() {
        Exception exception = new Exception("TEST");
        ServletWebRequest webRequest = makeServletWebRequest(makeHttpServletRequest());
        OAuth2ExceptionTranslator translator = makeExceptionTranslator(exception, INVALID_REQUEST_RESPONSE);
        SessionAttributeStore sessionAttributeStore = makeSessionAttributeStore(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null);
        OAuth2ClientDetailsService clientDetailsService = makeEmptyClientDetailsService();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                clientDetailsService,
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(makeAuthorizedAuthentication(), makeClientDetails(), SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setSessionAttributeStore(sessionAttributeStore);
        endpoint.setExceptionTranslator(translator);

        ModelAndView modelAndView = endpoint.handleOtherException(exception, webRequest);
        verify(clientDetailsService, times(1)).loadClientDetailsByClientId(RAW_CLIENT_ID);
        assertEquals("/oauth/error", modelAndView.getViewName());
        Assertions.assertEquals(INVALID_REQUEST_ERROR, modelAndView.getModel().get("error"));
    }

    @Test
    @DisplayName("세션에 인가 요청에 대한 정보가 있지 않으며 예외 처리 도중 요청 받은 리다이렉트 주소가 유효 하지 않을때")
    void whenSessionNotHasAuthorizationRequestAndRequestedRedirectUriIsNotAllowedDuringExceptionHandling() {
        Exception exception = new Exception("TEST");
        ServletWebRequest webRequest = makeServletWebRequest(makeHttpServletRequest());
        OAuth2ClientDetails clientDetails = makeClientDetails();
        RedirectResolver redirectResolver = makeMismatchRedirectResolver(clientDetails, RAW_REDIRECT_URI);
        OAuth2ExceptionTranslator translator = makeExceptionTranslator(exception, INVALID_REQUEST_RESPONSE);
        SessionAttributeStore sessionAttributeStore = makeSessionAttributeStore(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(makeAuthorizedAuthentication(), makeClientDetails(), SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setSessionAttributeStore(sessionAttributeStore);
        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setExceptionTranslator(translator);

        ModelAndView modelAndView = endpoint.handleOtherException(exception, webRequest);
        verify(redirectResolver, times(1)).resolveRedirectURI(RAW_REDIRECT_URI, clientDetails);
        assertEquals("/oauth/error", modelAndView.getViewName());
        Assertions.assertEquals(INVALID_REQUEST_ERROR, modelAndView.getModel().get("error"));
    }

    @Test
    @DisplayName("세션에 인가 요청 정보가 없으며 요청 정보에 state 속성이 존재할 때 예외 처리")
    void exceptionHandlingWhenSessionNotHasAuthorizationRequestAndRequestHasStateAttribute() {
        Exception exception = new Exception("TEST");
        HttpServletRequest request = makeHttpServletRequest();
        ServletWebRequest webRequest = makeServletWebRequest(request);
        OAuth2ClientDetails clientDetails = makeClientDetails();
        RedirectResolver redirectResolver = makeRedirectResolver(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI);
        OAuth2ExceptionTranslator translator = makeExceptionTranslator(exception, INVALID_REQUEST_RESPONSE);
        SessionAttributeStore sessionAttributeStore = makeSessionAttributeStore(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(makeAuthorizedAuthentication(), makeClientDetails(), SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setSessionAttributeStore(sessionAttributeStore);
        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setExceptionTranslator(translator);
        when(request.getParameter(AuthorizationRequestKey.STATE)).thenReturn(STATE);

        ModelAndView modelAndView = endpoint.handleOtherException(exception, webRequest);
        assertNotNull(modelAndView.getView());
        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
        assertEquals(INVALID_REQUEST_ERROR.getErrorCode(), modelAndView.getModel().get("error_code"));
        assertEquals(INVALID_REQUEST_ERROR.getDescription(), modelAndView.getModel().get("error_description"));
        assertEquals(STATE, modelAndView.getModel().get("state"));
    }

    @Test
    @DisplayName("세션에 인가 요청 정보가 없으며 요청 정보에 state 속성이 없을 때 예외 처리")
    void exceptionHandlingWhenSessionNotHasAuthorizationRequestAndRequestNotHasStateAttribute() {
        Exception exception = new Exception("TEST");
        HttpServletRequest request = makeHttpServletRequest();
        ServletWebRequest webRequest = makeServletWebRequest(request);
        OAuth2ClientDetails clientDetails = makeClientDetails();
        RedirectResolver redirectResolver = makeRedirectResolver(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI);
        OAuth2ExceptionTranslator translator = makeExceptionTranslator(exception, INVALID_REQUEST_RESPONSE);
        SessionAttributeStore sessionAttributeStore = makeSessionAttributeStore(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(makeAuthorizedAuthentication(), makeClientDetails(), SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setSessionAttributeStore(sessionAttributeStore);
        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setExceptionTranslator(translator);
        when(request.getParameter(AuthorizationRequestKey.STATE)).thenReturn(null);

        ModelAndView modelAndView = endpoint.handleOtherException(exception, webRequest);
        assertNotNull(modelAndView.getView());
        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
        assertEquals(INVALID_REQUEST_ERROR.getErrorCode(), modelAndView.getModel().get("error_code"));
        assertEquals(INVALID_REQUEST_ERROR.getDescription(), modelAndView.getModel().get("error_description"));
        assertNull(modelAndView.getModel().get("state"));
    }

    @Test
    @DisplayName("세션에 인가 요청에 대한 정보가 있으며 예외 처리 도중 클라이언트 정보 검색 예외가 발생 했을때")
    void whenSessionHasAuthorizationRequestAndThrowsClientRegistrationExceptionDuringExceptionHandling() {
        Exception exception = new Exception("TEST");
        ServletWebRequest webRequest = makeServletWebRequest();
        OAuth2ExceptionTranslator translator = makeExceptionTranslator(exception, INVALID_REQUEST_RESPONSE);
        AuthorizationRequest authorizationRequest = makeAuthorizationRequest();
        SessionAttributeStore sessionAttributeStore = makeSessionAttributeStore(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, authorizationRequest);
        OAuth2ClientDetailsService clientDetailsService = makeEmptyClientDetailsService();
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                clientDetailsService,
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(makeAuthorizedAuthentication(), makeClientDetails(), SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setSessionAttributeStore(sessionAttributeStore);
        endpoint.setExceptionTranslator(translator);

        ModelAndView modelAndView = endpoint.handleOtherException(exception, webRequest);
        verify(clientDetailsService, times(1)).loadClientDetailsByClientId(RAW_CLIENT_ID);
        assertEquals("/oauth/error", modelAndView.getViewName());
        Assertions.assertEquals(INVALID_REQUEST_ERROR, modelAndView.getModel().get("error"));
    }

    @Test
    @DisplayName("세션에 인가 요청에 대한 정보가 있으며 예외 처리 도중 요청 받은 리다이렉트 주소가 유효 하지 않을때")
    void whenSessionHasAuthorizationRequestAndRequestedRedirectUriIsNotAllowedDuringExceptionHandling() {
        Exception exception = new Exception("TEST");
        ServletWebRequest webRequest = makeServletWebRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        RedirectResolver redirectResolver = makeMismatchRedirectResolver(clientDetails, RAW_RESOLVED_REDIRECT_URI);
        OAuth2ExceptionTranslator translator = makeExceptionTranslator(exception, INVALID_REQUEST_RESPONSE);
        SessionAttributeStore sessionAttributeStore = makeSessionAttributeStore(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, makeAuthorizationRequest());
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(makeAuthorizedAuthentication(), makeClientDetails(), SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setSessionAttributeStore(sessionAttributeStore);
        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setExceptionTranslator(translator);

        ModelAndView modelAndView = endpoint.handleOtherException(exception, webRequest);
        verify(redirectResolver, times(1)).resolveRedirectURI(RAW_RESOLVED_REDIRECT_URI, clientDetails);
        assertEquals("/oauth/error", modelAndView.getViewName());
        Assertions.assertEquals(INVALID_REQUEST_ERROR, modelAndView.getModel().get("error"));
    }

    @Test
    @DisplayName("세션에 인가 요청 정보가 있으며 요청 정보에 state 속성이 존재할 때 예외 처리")
    void exceptionHandlingWhenSessionHasAuthorizationRequestAndRequestHasStateAttribute() {
        Exception exception = new Exception("TEST");
        AuthorizationRequest authorizationRequest = makeAuthorizationRequest();
        ServletWebRequest webRequest = makeServletWebRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        RedirectResolver redirectResolver = makeRedirectResolver(clientDetails, RAW_RESOLVED_REDIRECT_URI, RESOLVED_REDIRECT_URI);
        OAuth2ExceptionTranslator translator = makeExceptionTranslator(exception, INVALID_REQUEST_RESPONSE);
        SessionAttributeStore sessionAttributeStore = makeSessionAttributeStore(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, authorizationRequest);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(makeAuthorizedAuthentication(), makeClientDetails(), SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setSessionAttributeStore(sessionAttributeStore);
        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setExceptionTranslator(translator);
        when(authorizationRequest.getState()).thenReturn(STATE);

        ModelAndView modelAndView = endpoint.handleOtherException(exception, webRequest);
        assertNotNull(modelAndView.getView());
        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
        assertEquals(INVALID_REQUEST_ERROR.getErrorCode(), modelAndView.getModel().get("error_code"));
        assertEquals(INVALID_REQUEST_ERROR.getDescription(), modelAndView.getModel().get("error_description"));
        assertEquals(STATE, modelAndView.getModel().get("state"));
    }

    @Test
    @DisplayName("세션에 인가 요청 정보가 있으며 요청 정보에 state 속성이 없을 때 예외 처리")
    void exceptionHandlingWhenSessionHasAuthorizationRequestAndRequestNotHasStateAttribute() {
        Exception exception = new Exception("TEST");
        AuthorizationRequest authorizationRequest = makeAuthorizationRequest();
        ServletWebRequest webRequest = makeServletWebRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        RedirectResolver redirectResolver = makeRedirectResolver(clientDetails, RAW_RESOLVED_REDIRECT_URI, RESOLVED_REDIRECT_URI);
        OAuth2ExceptionTranslator translator = makeExceptionTranslator(exception, INVALID_REQUEST_RESPONSE);
        SessionAttributeStore sessionAttributeStore = makeSessionAttributeStore(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, authorizationRequest);
        AuthorizationEndpoint endpoint = new AuthorizationEndpoint(
                makeClientDetailsService(RAW_CLIENT_ID, clientDetails),
                makeAuthorityDetailsService(),
                makeResponseEnhancer(),
                makeAutoApprovalScopeHandler(makeAuthorizedAuthentication(), makeClientDetails(), SCOPE, REQUIRED_APPROVAL_SCOPES));

        endpoint.setSessionAttributeStore(sessionAttributeStore);
        endpoint.setRedirectResolver(redirectResolver);
        endpoint.setExceptionTranslator(translator);
        when(authorizationRequest.getState()).thenReturn(null);

        ModelAndView modelAndView = endpoint.handleOtherException(exception, webRequest);
        assertNotNull(modelAndView.getView());
        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
        assertEquals(INVALID_REQUEST_ERROR.getErrorCode(), modelAndView.getModel().get("error_code"));
        assertEquals(INVALID_REQUEST_ERROR.getDescription(), modelAndView.getModel().get("error_description"));
        assertNull(modelAndView.getModel().get("state"));
    }

    private void assertStoredRequest(Map<String, Object> model, Map<String, String> parameter, ModelAndView modelAndView, AuthorizationRequest storedRequest) {
        assertEquals(RAW_CLIENT_ID, storedRequest.getClientId());
        assertEquals(RAW_USERNAME, storedRequest.getUsername());
        assertEquals(STATE, storedRequest.getState());
        assertEquals(RESOLVED_REDIRECT_URI, storedRequest.getRedirectUri());
        assertEquals(parameter, model.get(AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE));
        assertEquals("forward:" + FORWARD_PAGE, modelAndView.getViewName());
        assertEquals(CLIENT_NAME, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_CLIENT_NAME));
    }
}
