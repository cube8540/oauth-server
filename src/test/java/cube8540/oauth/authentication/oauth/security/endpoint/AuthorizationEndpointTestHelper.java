package cube8540.oauth.authentication.oauth.security.endpoint;

import cube8540.oauth.authentication.oauth.security.AutoApprovalScopeHandler;
import cube8540.oauth.authentication.security.AuthorityDetails;
import cube8540.oauth.authentication.security.AuthorityDetailsService;
import cube8540.oauth.authentication.oauth.AuthorizationRequestKey;
import cube8540.oauth.authentication.oauth.client.domain.ClientNotFoundException;
import cube8540.oauth.authentication.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.oauth.security.AuthorizationCode;
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.oauth.security.OAuth2AuthorizationCodeGenerator;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.web.bind.support.SessionAttributeStore;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.security.Principal;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static cube8540.oauth.authentication.oauth.OAuth2UtilsKt.extractScopes;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthorizationEndpointTestHelper {

    static final String TOKEN_TYPE = "Bearer";

    static final String RAW_ACCESS_TOKEN_ID = "ACCESS-TOKEN-ID";

    static final String RAW_AUTHORIZATION_CODE = "AUTHORIZATION_CODE";
    static final AuthorizationCode AUTHORIZATION_CODE = new AuthorizationCode(RAW_AUTHORIZATION_CODE);

    static final String RAW_CLIENT_ID = "CLIENT-ID";

    static final String CLIENT_NAME = "CLIENT-NAME";

    static final String STATE = "STATE";

    static final String RESPONSE_TYPE = OAuth2AuthorizationResponseType.CODE.getValue();

    static final String RAW_REDIRECT_URI = "http://localhost:8080";
    static final String RAW_RESOLVED_REDIRECT_URI = "http://localhost:8081";
    static final URI RESOLVED_REDIRECT_URI = URI.create(RAW_RESOLVED_REDIRECT_URI);

    static final String RAW_SCOPE = "SCOPE-1 SCOPE-2 SCOPE-3";
    static final Set<String> SCOPE = extractScopes(RAW_SCOPE);
    static final Collection<AuthorityDetails> SCOPE_DETAILS = Arrays.asList(
            mock(AuthorityDetails.class), mock(AuthorityDetails.class), mock(AuthorityDetails.class));
    static final Collection<AuthorityDetails> CLIENT_SCOPE_DETAILS = Arrays.asList(
            mock(AuthorityDetails.class), mock(AuthorityDetails.class), mock(AuthorityDetails.class));
    static final Set<String> RAW_RESOLVED_SCOPES = new HashSet<>(Arrays.asList("RESOLVED-SCOPE-1", "RESOLVED-SCOPE-2", "RESOLVED-SCOPE-3"));

    static final Set<String> CLIENT_SCOPE = new HashSet<>(Arrays.asList("CLIENT-SCOPE-1", "CLIENT-SCOPE-2", "CLIENT-SCOPE-3"));

    static final String RAW_USERNAME = "username";

    static final String FORWARD_PAGE = "/forward";

    static final OAuth2Error INVALID_GRANT_ERROR = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT);
    static final ResponseEntity<OAuth2Error> INVALID_GRANT_RESPONSE = new ResponseEntity<>(INVALID_GRANT_ERROR, HttpStatus.UNAUTHORIZED);

    static final OAuth2Error INVALID_REQUEST_ERROR = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
    static final ResponseEntity<OAuth2Error> INVALID_REQUEST_RESPONSE = new ResponseEntity<>(INVALID_REQUEST_ERROR, HttpStatus.BAD_REQUEST);

    static final OAuth2Error UNAUTHORIZED_CLIENT_ERROR = new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    static final ResponseEntity<OAuth2Error> UNAUTHORIZED_CLIENT_RESPONSE = new ResponseEntity<>(UNAUTHORIZED_CLIENT_ERROR, HttpStatus.UNAUTHORIZED);

    static final LocalDateTime EXPIRATION_DATETIME = LocalDateTime.of(2020, 1, 24, 21, 24, 0);
    static final long EXPIRATION_IN = 600000;

    static final Map<String, String> ADDITIONAL_INFO = new HashMap<>();

    static final Set<String> REQUIRED_APPROVAL_SCOPES = new HashSet<>(Arrays.asList("REQUIRED-SCOPE-1", "REQUIRED-SCOPE-2", "REQUIRED-SCOPE-3"));
    static final Collection<AuthorityDetails>  REQUIRED_APPROVAL_SCOPE_DETAILS = Arrays.asList(
            mock(AuthorityDetails.class), mock(AuthorityDetails.class), mock(AuthorityDetails.class));

    static Map<String, Object> makeEmptyModel() {
        Map<String, Object> model = new HashMap<>();

        model.put(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null);
        model.put(AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE, null);

        return model;
    }

    static Map<String, Object> makeModel(Map<?, ?> originalRequest, AuthorizationRequest request) {
        Map<String, Object> model = makeEmptyModel();

        model.put(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, request);
        model.put(AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE, originalRequest);

        return model;
    }

    static AuthorizationRequest makeAuthorizationRequest() {
        AuthorizationRequest request = mock(AuthorizationRequest.class);

        when(request.getClientId()).thenReturn(RAW_CLIENT_ID);
        when(request.getUsername()).thenReturn(RAW_USERNAME);
        when(request.getState()).thenReturn(STATE);
        when(request.getRedirectUri()).thenReturn(RESOLVED_REDIRECT_URI);
        when(request.getRequestScopes()).thenReturn(SCOPE);
        when(request.getResponseType()).thenReturn(OAuth2AuthorizationResponseType.CODE);

        return request;
    }

    static Map<String, String> makeEmptyApprovalParameter() {
        return new HashMap<>();
    }

    static Map<String, String> makeRequestParameter() {
        Map<String, String> parameter = new HashMap<>();
        parameter.put(AuthorizationRequestKey.STATE, STATE);
        parameter.put(AuthorizationRequestKey.REDIRECT_URI, RAW_REDIRECT_URI);
        parameter.put(AuthorizationRequestKey.CLIENT_ID, RAW_CLIENT_ID);
        parameter.put(AuthorizationRequestKey.SCOPE, RAW_SCOPE);
        parameter.put(AuthorizationRequestKey.RESPONSE_TYPE, RESPONSE_TYPE);
        return parameter;
    }

    static HttpServletRequest makeHttpServletRequest() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter(AuthorizationRequestKey.CLIENT_ID)).thenReturn(RAW_CLIENT_ID);
        when(request.getParameter(AuthorizationRequestKey.REDIRECT_URI)).thenReturn(RAW_REDIRECT_URI);
        return request;
    }

    static Principal makeAuthenticationTypeNotAuthentication() {
        return mock(Principal.class);
    }

    static Authentication makeAuthorizedAuthentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(RAW_USERNAME);
        when(authentication.isAuthenticated()).thenReturn(true);
        return authentication;
    }

    static Authentication makeNotAuthorizedAuthentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(RAW_USERNAME);
        when(authentication.isAuthenticated()).thenReturn(false);
        return authentication;
    }

    static AuthorizationResponseEnhancer makeResponseEnhancer() {
        AuthorizationResponseEnhancer enhancer = mock(AuthorizationResponseEnhancer.class);

        doAnswer(returnsFirstArg()).when(enhancer).enhance(any(), any());
        return enhancer;
    }

    static AuthorityDetailsService makeAuthorityDetailsService() {
        AuthorityDetailsService service = mock(AuthorityDetailsService.class);

        when(service.loadAuthorityByAuthorityCodes(SCOPE)).thenReturn(SCOPE_DETAILS);
        when(service.loadAuthorityByAuthorityCodes(CLIENT_SCOPE)).thenReturn(CLIENT_SCOPE_DETAILS);
        when(service.loadAuthorityByAuthorityCodes(REQUIRED_APPROVAL_SCOPES)).thenReturn(REQUIRED_APPROVAL_SCOPE_DETAILS);

        return service;
    }

    static OAuth2ClientDetails makeClientDetails() {
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);

        when(clientDetails.getClientId()).thenReturn(RAW_CLIENT_ID);
        when(clientDetails.getClientName()).thenReturn(CLIENT_NAME);
        when(clientDetails.getScopes()).thenReturn(CLIENT_SCOPE);

        return clientDetails;
    }

    static OAuth2ClientDetailsService makeClientDetailsService(String clientId, OAuth2ClientDetails client) {
        OAuth2ClientDetailsService service = mock(OAuth2ClientDetailsService.class);

        when(service.loadClientDetailsByClientId(clientId)).thenReturn(client);

        return service;
    }

    static OAuth2ClientDetailsService makeEmptyClientDetailsService() {
        OAuth2ClientDetailsService service = mock(OAuth2ClientDetailsService.class);

        when(service.loadClientDetailsByClientId(any())).thenThrow(ClientNotFoundException.instance("TEST"));

        return service;
    }

    static OAuth2RequestValidator makeErrorRequestValidator(OAuth2ClientDetails clientDetails, Set<String> scopes) {
        OAuth2RequestValidator validator = mock(OAuth2RequestValidator.class);

        when(validator.validateScopes(clientDetails, scopes)).thenReturn(false);

        return validator;
    }

    static OAuth2RequestValidator makePassRequestValidator(OAuth2ClientDetails clientDetails, Set<String> scopes) {
        OAuth2RequestValidator validator = mock(OAuth2RequestValidator.class);

        when(validator.validateScopes(clientDetails, scopes)).thenReturn(true);

        return validator;
    }

    static RedirectResolver makeRedirectResolver(OAuth2ClientDetails clientDetails, String target, URI result) {
        RedirectResolver resolver = mock(RedirectResolver.class);

        when(resolver.resolveRedirectURI(target, clientDetails)).thenReturn(result);

        return resolver;
    }

    static RedirectResolver makeMismatchRedirectResolver(OAuth2ClientDetails clientDetails, String target) {
        RedirectResolver resolver = mock(RedirectResolver.class);

        when(resolver.resolveRedirectURI(target, clientDetails)).thenThrow(new RedirectMismatchException(target + " is not registered"));

        return resolver;
    }

    static ScopeApprovalResolver makeScopeApprovalResolver(AuthorizationRequest authorizationRequest, Map<String, String> approvalRequest, Set<String> results) {
        ScopeApprovalResolver resolver = mock(ScopeApprovalResolver.class);

        when(resolver.resolveApprovalScopes(authorizationRequest, approvalRequest)).thenReturn(results);

        return resolver;
    }

    static SessionStatus makeSessionStatus() {
        return mock(SessionStatus.class);
    }

    static SessionAttributeStore makeSessionAttributeStore(ServletWebRequest webRequest, String key, Object results) {
        SessionAttributeStore attributeStore = mock(SessionAttributeStore.class);

        when(attributeStore.retrieveAttribute(webRequest, key)).thenReturn(results);

        return attributeStore;
    }

    static OAuth2ExceptionTranslator makeExceptionTranslator(Exception exception, ResponseEntity<OAuth2Error> response) {
        OAuth2ExceptionTranslator translator = mock(OAuth2ExceptionTranslator.class);

        when(translator.translate(exception)).thenReturn(response);

        return translator;
    }

    static ServletWebRequest makeServletWebRequest() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        return new ServletWebRequest(request, response);
    }

    static ServletWebRequest makeServletWebRequest(HttpServletRequest request) {
        HttpServletResponse response = mock(HttpServletResponse.class);

        return new ServletWebRequest(request, response);
    }

    static OAuth2AuthorizationCodeGenerator makeAuthorizationCodeGenerator(AuthorizationCode code) {
        OAuth2AuthorizationCodeGenerator generator = mock(OAuth2AuthorizationCodeGenerator.class);

        when(generator.generateNewAuthorizationCode(any())).thenReturn(code);

        return generator;
    }

    static OAuth2AccessTokenDetails makeAccessToken() {
        OAuth2AccessTokenDetails accessToken = mock(OAuth2AccessTokenDetails.class);
        when(accessToken.getTokenValue()).thenReturn(RAW_ACCESS_TOKEN_ID);
        when(accessToken.getTokenType()).thenReturn(TOKEN_TYPE);
        when(accessToken.getClientId()).thenReturn(RAW_CLIENT_ID);
        when(accessToken.getUsername()).thenReturn(RAW_USERNAME);
        when(accessToken.getScopes()).thenReturn(RAW_RESOLVED_SCOPES);
        when(accessToken.getExpiration()).thenReturn(EXPIRATION_DATETIME);
        when(accessToken.getExpiresIn()).thenReturn(EXPIRATION_IN);
        when(accessToken.getAdditionalInformation()).thenReturn(ADDITIONAL_INFO);
        return accessToken;
    }

    static OAuth2AccessTokenGranter makeTokenGranter(OAuth2AccessTokenDetails accessToken) {
        OAuth2AccessTokenGranter granter = mock(OAuth2AccessTokenGranter.class);

        when(granter.grant(any(), any())).thenReturn(accessToken);

        return granter;
    }

    static AutoApprovalScopeHandler makeAutoApprovalScopeHandler(Principal authentication, OAuth2ClientDetails clientDetails, Set<String> requestScopes) {
        AutoApprovalScopeHandler handler = mock(AutoApprovalScopeHandler.class);

        when(handler.filterRequiredPermissionScopes(authentication, clientDetails, requestScopes))
                .thenReturn(REQUIRED_APPROVAL_SCOPES);

        return handler;
    }

    static AutoApprovalScopeHandler makeAllApprovalScopeHandler(Principal authentication, OAuth2ClientDetails clientDetails, Set<String> requestScopes) {
        AutoApprovalScopeHandler handler = mock(AutoApprovalScopeHandler.class);

        when(handler.filterRequiredPermissionScopes(authentication, clientDetails, requestScopes)).thenReturn(Collections.emptySet());

        return handler;
    }
}
