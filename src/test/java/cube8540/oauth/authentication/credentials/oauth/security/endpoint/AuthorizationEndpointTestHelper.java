package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ClientRegistrationException;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2RequestValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.web.bind.support.SessionAttributeStore;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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
    static final Set<String> SCOPE = OAuth2Utils.extractScopes(RAW_SCOPE);
    static final Collection<AuthorityDetails> SCOPE_DETAILS = Arrays.asList(
            mock(AuthorityDetails.class), mock(AuthorityDetails.class), mock(AuthorityDetails.class));
    static final Collection<AuthorityDetails> CLIENT_SCOPE_DETAILS = Arrays.asList(
            mock(AuthorityDetails.class), mock(AuthorityDetails.class), mock(AuthorityDetails.class));
    static final Set<String> RAW_RESOLVED_SCOPES = new HashSet<>(Arrays.asList("RESOLVED-SCOPE-1", "RESOLVED-SCOPE-2", "RESOLVED-SCOPE-3"));

    static final Set<String> CLIENT_SCOPE = new HashSet<>(Arrays.asList("CLIENT-SCOPE-1", "CLIENT-SCOPE-2", "CLIENT-SCOPE-3"));

    static final String RAW_USERNAME = "email@email.com";

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

    static Authentication mockAuthorizedAuthentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(RAW_USERNAME);
        when(authentication.isAuthenticated()).thenReturn(true);
        return authentication;
    }

    static Authentication mockNotAuthorizedAuthentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(RAW_USERNAME);
        when(authentication.isAuthenticated()).thenReturn(false);
        return authentication;
    }

    static AuthorizationResponseEnhancer mockResponseEnhancer() {
        AuthorizationResponseEnhancer enhancer = mock(AuthorizationResponseEnhancer.class);

        doAnswer(returnsFirstArg()).when(enhancer).enhance(any(), any());
        return enhancer;
    }

    static MockAuthorizationRequestMap mockAuthorizationRequestMap() {
        return new MockAuthorizationRequestMap();
    }

    static MockRequestValidator mockRequestValidator() {
        return new MockRequestValidator();
    }

    static MockRedirectResolver mockRedirectResolver() {
        return new MockRedirectResolver();
    }

    static MockScopeDetailsService mockScopeDetailsService() {
        return new MockScopeDetailsService();
    }

    static MockCodeGenerator mockCodeGenerator() {
        return new MockCodeGenerator();
    }

    static MockClientDetails mockClientDetails() {
        return new MockClientDetails();
    }

    static MockClientDetailsService mockClientDetailsService() {
        return new MockClientDetailsService();
    }

    static MockAuthorizationRequest mockAuthorizationRequest() {
        return new MockAuthorizationRequest();
    }

    static MockScopeApprovalResolver mockScopeApprovalResolver() {
        return new MockScopeApprovalResolver();
    }

    static MockExceptionTranslator mockExceptionTranslator() {
        return new MockExceptionTranslator();
    }

    static MockHttpServletRequest mockHttpServletRequest() {
        return new MockHttpServletRequest();
    }

    static MockSessionAttributeStore mockSessionAttributeStore() {
        return new MockSessionAttributeStore();
    }

    static MockOAuth2AccessTokenGranter mockAccessTokenGranter() {
        return new MockOAuth2AccessTokenGranter();
    }

    static MockAccessToken mockAccessToken() {
        return new MockAccessToken();
    }

    static class MockAuthorizationRequestMap {
        private Map<String, String> requestMap;

        private MockAuthorizationRequestMap() {
            this.requestMap = new HashMap<>();
        }

        MockAuthorizationRequestMap configDefault() {
            this.requestMap.put(OAuth2Utils.AuthorizationRequestKey.STATE, STATE);
            this.requestMap.put(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI, RAW_REDIRECT_URI);
            this.requestMap.put(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID, RAW_CLIENT_ID);
            this.requestMap.put(OAuth2Utils.AuthorizationRequestKey.SCOPE, RAW_SCOPE);
            this.requestMap.put(OAuth2Utils.AuthorizationRequestKey.RESPONSE_TYPE, RESPONSE_TYPE);
            return this;
        }

        MockAuthorizationRequestMap configResponseType(String responseType) {
            this.requestMap.put(OAuth2Utils.AuthorizationRequestKey.RESPONSE_TYPE, responseType);
            return this;
        }

        MockAuthorizationRequestMap configScopeNull() {
            this.requestMap.put(OAuth2Utils.AuthorizationRequestKey.SCOPE, null);
            return this;
        }

        Map<String, String> build() {
            return requestMap;
        }
    }

    static class MockClientDetails {
        private OAuth2ClientDetails client;

        private MockClientDetails() {
            this.client = mock(OAuth2ClientDetails.class);
        }

        MockClientDetails configDefault() {
            when(client.getClientId()).thenReturn(RAW_CLIENT_ID);
            when(client.getClientName()).thenReturn(CLIENT_NAME);
            when(client.getScopes()).thenReturn(CLIENT_SCOPE);
            return this;
        }

        OAuth2ClientDetails build() {
            return client;
        }
    }

    static class MockClientDetailsService {
        private OAuth2ClientDetailsService service;

        private MockClientDetailsService() {
            this.service = mock(OAuth2ClientDetailsService.class);
        }

        MockClientDetailsService registerClient(OAuth2ClientDetails clientDetails) {
            when(service.loadClientDetailsByClientId(RAW_CLIENT_ID)).thenReturn(clientDetails);
            return this;
        }

        MockClientDetailsService emptyClient() {
            when(service.loadClientDetailsByClientId(RAW_CLIENT_ID)).thenThrow(new OAuth2ClientRegistrationException("NOT FOUND"));
            return this;
        }

        OAuth2ClientDetailsService build() {
            return service;
        }
    }

    static class MockRequestValidator {
        private OAuth2RequestValidator validator;

        private MockRequestValidator() {
            this.validator = mock(OAuth2RequestValidator.class);
        }

        MockRequestValidator configAllowedScopes(OAuth2ClientDetails clientDetails, Set<String> scopes) {
            when(validator.validateScopes(clientDetails, scopes)).thenReturn(true);
            return this;
        }

        MockRequestValidator configNotAllowedScopes(OAuth2ClientDetails clientDetails, Set<String> scopes) {
            when(validator.validateScopes(clientDetails, scopes)).thenReturn(false);
            return this;
        }

        OAuth2RequestValidator build() {
            return validator;
        }
    }

    static class MockRedirectResolver {
        private RedirectResolver redirectResolver;

        private MockRedirectResolver() {
            this.redirectResolver = mock(RedirectResolver.class);
        }

        MockRedirectResolver configResolve(OAuth2ClientDetails clientDetails, String resolveTarget, URI result) {
            when(redirectResolver.resolveRedirectURI(resolveTarget, clientDetails)).thenReturn(result);
            return this;
        }

        MockRedirectResolver configMismatched(OAuth2ClientDetails clientDetails, String resolveTarget) {
            when(redirectResolver.resolveRedirectURI(resolveTarget, clientDetails)).thenThrow(new RedirectMismatchException("TEST"));
            return this;
        }

        RedirectResolver build() {
            return redirectResolver;
        }
    }

    static class MockScopeDetailsService {
        private AuthorityDetailsService service;

        private MockScopeDetailsService() {
            this.service = mock(AuthorityDetailsService.class);
        }

        MockScopeDetailsService registerScopes(Collection<String> where, Collection<AuthorityDetails> result) {
            when(service.loadAuthorityByAuthorityCodes(where)).thenReturn(result);
            return this;
        }

        AuthorityDetailsService build() {
            return service;
        }
    }

    static class MockCodeGenerator {
        private OAuth2AuthorizationCodeGenerator generator;

        private MockCodeGenerator() {
            this.generator = mock(OAuth2AuthorizationCodeGenerator.class);
        }

        MockCodeGenerator configGenerated() {
            when(generator.generateNewAuthorizationCode(any())).thenReturn(AUTHORIZATION_CODE);
            return this;
        }

        OAuth2AuthorizationCodeGenerator build() {
            return generator;
        }
    }

    static class MockAuthorizationRequest {
        private AuthorizationRequest authorizationRequest;

        private MockAuthorizationRequest() {
            this.authorizationRequest = mock(AuthorizationRequest.class);
        }

        MockAuthorizationRequest configDefault() {
            when(authorizationRequest.getClientId()).thenReturn(RAW_CLIENT_ID);
            when(authorizationRequest.getUsername()).thenReturn(RAW_USERNAME);
            when(authorizationRequest.getRedirectUri()).thenReturn(RESOLVED_REDIRECT_URI);
            when(authorizationRequest.getRequestScopes()).thenReturn(SCOPE);
            return this;
        }

        MockAuthorizationRequest configNullState() {
            when(authorizationRequest.getState()).thenReturn(null);
            return this;
        }

        MockAuthorizationRequest configState() {
            when(authorizationRequest.getState()).thenReturn(STATE);
            return this;
        }

        MockAuthorizationRequest configResponseType(OAuth2AuthorizationResponseType responseType) {
            when(authorizationRequest.getResponseType()).thenReturn(responseType);
            return this;
        }

        AuthorizationRequest build() {
            return authorizationRequest;
        }
    }

    static class MockScopeApprovalResolver {
        private ScopeApprovalResolver resolver;

        private MockScopeApprovalResolver() {
            this.resolver = mock(ScopeApprovalResolver.class);
        }

        MockScopeApprovalResolver configResolve(AuthorizationRequest request, Map<String, String> approvalRequest, Set<String> result) {
            when(resolver.resolveApprovalScopes(request, approvalRequest)).thenReturn(result);
            return this;
        }

        ScopeApprovalResolver build() {
            return resolver;
        }
    }

    static class MockExceptionTranslator {
        private OAuth2ExceptionTranslator translator;

        private MockExceptionTranslator() {
            this.translator = mock(OAuth2ExceptionTranslator.class);
        }

        MockExceptionTranslator configTranslate(Exception e, ResponseEntity<OAuth2Error> result) {
            when(translator.translate(e)).thenReturn(result);
            return this;
        }

        OAuth2ExceptionTranslator build() {
            return translator;
        }
    }

    static class MockHttpServletRequest {
        private HttpServletRequest request;

        private MockHttpServletRequest() {
            this.request = mock(HttpServletRequest.class);
        }

        MockHttpServletRequest configDefault() {
            when(request.getParameter(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID)).thenReturn(RAW_CLIENT_ID);
            when(request.getParameter(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI)).thenReturn(RAW_REDIRECT_URI);
            return this;
        }

        MockHttpServletRequest configState() {
            when(request.getParameter(OAuth2Utils.AuthorizationRequestKey.STATE)).thenReturn(STATE);
            return this;
        }

        MockHttpServletRequest configNullState() {
            when(request.getParameter(OAuth2Utils.AuthorizationRequestKey.STATE)).thenReturn(null);
            return this;
        }

        HttpServletRequest build() {
            return request;
        }
    }

    static class MockSessionAttributeStore {
        private SessionAttributeStore store;

        private MockSessionAttributeStore() {
            this.store = mock(SessionAttributeStore.class);
        }

        MockSessionAttributeStore configRetrieveAttribute(ServletWebRequest webRequest, String key, Object result) {
            when(store.retrieveAttribute(webRequest, key)).thenReturn(result);
            return this;
        }

        SessionAttributeStore build() {
            return store;
        }
    }

    static class MockOAuth2AccessTokenGranter {
        private OAuth2AccessTokenGranter granter;

        private MockOAuth2AccessTokenGranter() {
            this.granter = mock(OAuth2AccessTokenGranter.class);
        }

        MockOAuth2AccessTokenGranter configToken(OAuth2AccessTokenDetails accessToken) {
            when(granter.grant(any(), any())).thenReturn(accessToken);
            return this;
        }

        OAuth2AccessTokenGranter build() {
            return granter;
        }
    }

    static class MockAccessToken {
        private OAuth2AccessTokenDetails accessToken;

        private MockAccessToken() {
            this.accessToken = mock(OAuth2AccessTokenDetails.class);
        }

        MockAccessToken configDefault() {
            when(accessToken.getTokenValue()).thenReturn(RAW_ACCESS_TOKEN_ID);
            when(accessToken.getTokenType()).thenReturn(TOKEN_TYPE);
            when(accessToken.getClientId()).thenReturn(RAW_CLIENT_ID);
            when(accessToken.getUsername()).thenReturn(RAW_USERNAME);
            when(accessToken.getScopes()).thenReturn(RAW_RESOLVED_SCOPES);
            when(accessToken.getExpiration()).thenReturn(EXPIRATION_DATETIME);
            when(accessToken.getExpiresIn()).thenReturn(EXPIRATION_IN);
            when(accessToken.getAdditionalInformation()).thenReturn(ADDITIONAL_INFO);
            return this;
        }

        OAuth2AccessTokenDetails build() {
            return accessToken;
        }
    }
}
