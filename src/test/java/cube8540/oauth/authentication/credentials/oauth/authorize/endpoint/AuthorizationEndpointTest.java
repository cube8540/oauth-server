package cube8540.oauth.authentication.credentials.oauth.authorize.endpoint;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRegistrationException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.credentials.oauth.error.UnsupportedResponseTypeException;
import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetailsService;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.web.bind.support.SessionAttributeStore;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("인가 엔드포인트 테스트")
class AuthorizationEndpointTest {

    private static final String RAW_CODE = "CODE";
    private static final AuthorizationCode CODE = new AuthorizationCode(RAW_CODE);

    private static final String RAW_CLIENT_ID = "CLIENT-ID";

    private static final String CLIENT_NAME = "CLIENT-NAME";

    private static final String STATE = "STATE";

    private static final String RESPONSE_TYPE = OAuth2AuthorizationResponseType.CODE.getValue();

    private static final String RAW_REDIRECT_URI = "http://localhost:8080";
    private static final URI RESOLVED_REDIRECT_URI = URI.create("http://localhost:8081");

    private static final String RAW_SCOPE = "SCOPE-1 SCOPE-2 SCOPE-3";
    private static final Set<String> SCOPE = OAuth2Utils.extractScopes(RAW_SCOPE);

    private static final Set<String> CLIENT_SCOPE = new HashSet<>(Arrays.asList("CLIENT-SCOPE-1", "CLIENT-SCOPE-2", "CLIENT-SCOPE-3"));

    private static final String RAW_USERNAME = "email@email.com";

    private static final String FORWARD_PAGE = "/forward";

    private OAuth2ClientDetailsService clientDetailsService;
    private OAuth2ScopeDetailsService scopeDetailsService;
    private OAuth2AuthorizationCodeGenerator codeGenerator;

    private AuthorizationEndpoint endpoint;

    @BeforeEach
    void setup() {
        this.clientDetailsService = mock(OAuth2ClientDetailsService.class);
        this.scopeDetailsService = mock(OAuth2ScopeDetailsService.class);
        this.codeGenerator = mock(OAuth2AuthorizationCodeGenerator.class);

        this.endpoint = new AuthorizationEndpoint(clientDetailsService, scopeDetailsService, codeGenerator);
    }

    @Nested
    @DisplayName("인가")
    class Authorize {

        @Nested
        @DisplayName("인증 정보가 Authentication 타입이 아닐시")
        class WhenPrincipalTypeIsNotAuthentication {

            private Map<String, String> parameter;
            private Map<String, Object> model;
            private Principal principal;

            @BeforeEach
            @SuppressWarnings("unchecked")
            void setup() {
                this.parameter = mock(Map.class);
                this.model = mock(Map.class);
                this.principal = mock(Principal.class);
            }

            @Test
            @DisplayName("InsufficientAuthenticationException이 발생해야 한다.")
            void shouldThrowsInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.authorize(parameter, model, principal));
            }
        }

        @Nested
        @DisplayName("인증 정보의 인증 여부가 false일시")
        class WhenAuthenticationObjectIsNotAuthenticated {

            private Map<String, String> parameter;
            private Map<String, Object> model;
            private Authentication principal;

            @BeforeEach
            @SuppressWarnings("unchecked")
            void setup() {
                this.parameter = mock(Map.class);
                this.model = mock(Map.class);
                this.principal = mock(Authentication.class);

                when(principal.isAuthenticated()).thenReturn(false);
            }

            @Test
            @DisplayName("InsufficientAuthenticationException이 발생해야 한다.")
            void shouldThrowsInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.authorize(parameter, model, principal));
            }
        }

        @Nested
        @DisplayName("유저 인증을 완료한 요청일시")
        class WhenAuthenticationCompletedRequesting {

            private Map<String, Object> model;
            private Authentication principal;

            @BeforeEach
            void setup() {
                this.model = new HashMap<>();
                this.principal = mock(Authentication.class);

                when(principal.isAuthenticated()).thenReturn(true);
                when(principal.getName()).thenReturn(RAW_USERNAME);
            }

            @Nested
            @DisplayName("요청 받은 응답 타입이 null일시")
            class WhenRequestingResponseTypeIsNull {

                private Map<String, String> parameter;

                @BeforeEach
                void setup() {
                    this.parameter = new HashMap<>();

                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.RESPONSE_TYPE, null);
                }

                @Test
                @DisplayName("UnsupportedResponseTypeException이 발생해야 한다.")
                void shouldThrowsUnsupportedResponseTypeException() {
                    assertThrows(UnsupportedResponseTypeException.class, () -> endpoint.authorize(parameter, model, principal));
                }

            }

            @Nested
            @DisplayName("요청 받은 응답 타입이 code가 아닐시")
            class WhenRequestingResponseTypeIsNotCode {

                private Map<String, String> parameter;

                @BeforeEach
                void setup() {
                    this.parameter = new HashMap<>();

                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.RESPONSE_TYPE, OAuth2AuthorizationResponseType.TOKEN.getValue());
                }

                @Test
                @DisplayName("UnsupportedResponseTypeException이 발생해야 한다.")
                void shouldThrowsSupportedResponseTypeException() {
                    assertThrows(UnsupportedResponseTypeException.class, () -> endpoint.authorize(parameter, model, principal));
                }
            }

            @Nested
            @DisplayName("요청 받은 응답 타입이 code일시")
            class WhenRequestingResponseTypeIsCode {

                private Map<String, String> parameter;
                private OAuth2RequestValidator requestValidator;
                private OAuth2ClientDetails clientDetails;
                private Collection<OAuth2ScopeDetails> scopeDetails;
                private Collection<OAuth2ScopeDetails> clientScopeDetails;

                @BeforeEach
                void setup() {
                    this.scopeDetails = new ArrayList<>();
                    this.clientScopeDetails = new ArrayList<>();
                    this.parameter = new HashMap<>();
                    RedirectResolver redirectResolver = mock(RedirectResolver.class);
                    this.requestValidator = mock(OAuth2RequestValidator.class);
                    this.clientDetails = mock(OAuth2ClientDetails.class);
                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.STATE, STATE);
                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI, RAW_REDIRECT_URI);
                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID, RAW_CLIENT_ID);
                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.SCOPE, RAW_SCOPE);
                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.RESPONSE_TYPE, RESPONSE_TYPE);

                    this.scopeDetails.add(mock(OAuth2ScopeDetails.class));
                    this.scopeDetails.add(mock(OAuth2ScopeDetails.class));
                    this.scopeDetails.add(mock(OAuth2ScopeDetails.class));

                    this.clientScopeDetails.add(mock(OAuth2ScopeDetails.class));
                    this.clientScopeDetails.add(mock(OAuth2ScopeDetails.class));
                    this.clientScopeDetails.add(mock(OAuth2ScopeDetails.class));

                    when(clientDetailsService.loadClientDetailsByClientId(RAW_CLIENT_ID)).thenReturn(clientDetails);
                    when(redirectResolver.resolveRedirectURI(RAW_REDIRECT_URI, clientDetails)).thenReturn(RESOLVED_REDIRECT_URI);
                    when(requestValidator.validateScopes(clientDetails, SCOPE)).thenReturn(true);
                    when(codeGenerator.generateNewAuthorizationCode(any(AuthorizationRequest.class))).thenReturn(CODE);
                    when(clientDetails.scope()).thenReturn(CLIENT_SCOPE);
                    when(clientDetails.clientName()).thenReturn(CLIENT_NAME);
                    when(scopeDetailsService.loadScopeDetailsByScopeIds(SCOPE)).thenReturn(scopeDetails);
                    when(scopeDetailsService.loadScopeDetailsByScopeIds(CLIENT_SCOPE)).thenReturn(clientScopeDetails);

                    endpoint.setRedirectResolver(redirectResolver);
                    endpoint.setRequestValidator(requestValidator);
                    endpoint.setApprovalPage(FORWARD_PAGE);
                }

                @Nested
                @DisplayName("요청한 스코프가 유효하지 않을시")
                class WhenRequestingScopeIsNotAllowed {

                    @BeforeEach
                    void setup() {
                        when(requestValidator.validateScopes(clientDetails, SCOPE)).thenReturn(false);
                    }

                    @Test
                    @DisplayName("InvalidGrantException이 발생해야 한다.")
                    void shouldThrowsInvalidGrantException() {
                        assertThrows(InvalidGrantException.class, () -> endpoint.authorize(parameter, model, principal));
                    }

                    @AfterEach
                    void after() {
                        when(requestValidator.validateScopes(clientDetails, SCOPE)).thenReturn(true);
                    }
                }

                @Test
                @DisplayName("요청 받은 클라이언트 아이디를 세션에 저장해야 한다.")
                void shouldSaveRequestingClientIdToSession() {
                    endpoint.authorize(parameter, model, principal);

                    AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                    assertEquals(RAW_CLIENT_ID, storedRequest.clientId());
                }

                @Test
                @DisplayName("요청 받은 유저명을 세션에 저장해야 한다.")
                void shouldSaveRequestingUsernameToSession() {
                    endpoint.authorize(parameter, model, principal);

                    AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                    assertEquals(RAW_USERNAME, storedRequest.username());
                }

                @Test
                @DisplayName("요청 받은 STATE를 세션에 저장해야 한다.")
                void shouldSaveRequestingStateToSession() {
                    endpoint.authorize(parameter, model, principal);

                    AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                    assertEquals(STATE, storedRequest.state());
                }

                @Test
                @DisplayName("요청 받은 리다이렉트 주소를 세션에 저장해야 한다.")
                void shouldSaveRequestingRedirectUriToSession() {
                    endpoint.authorize(parameter, model, principal);

                    AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                    assertEquals(RESOLVED_REDIRECT_URI, storedRequest.redirectURI());
                }

                @Test
                @DisplayName("요청 받은 스코프를 세션에 저장해야 한다.")
                void shouldSaveRequestingScopeToSession() {
                    endpoint.authorize(parameter, model, principal);

                    AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                    assertEquals(SCOPE, storedRequest.requestScopes());
                }

                @Nested
                @DisplayName("요청한 스코프가 null일시")
                class WhenRequestingScopeIsNull {

                    @BeforeEach
                    void setup() {
                        parameter.put(OAuth2Utils.AuthorizationRequestKey.SCOPE, null);

                        when(requestValidator.validateScopes(clientDetails, null)).thenReturn(true);
                        when(requestValidator.validateScopes(clientDetails, Collections.emptySet())).thenReturn(true);
                    }

                    @Test
                    @DisplayName("클라이언트에 저장된 스코프를 세션에 저장해야 한다.")
                    void shouldSaveClientScopeToSession() {
                        endpoint.authorize(parameter, model, principal);

                        AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                        assertEquals(CLIENT_SCOPE, storedRequest.requestScopes());
                    }

                    @Test
                    @DisplayName("클라이언트에 저장된 스코프를 ModelAndView에 저장해야 한다.")
                    void shouldSaveClientScopeToModelAndView() {
                        ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);

                        assertEquals(clientScopeDetails, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_SCOPES_NAME));
                    }

                    @AfterEach
                    void after() {
                        parameter.put(OAuth2Utils.AuthorizationRequestKey.SCOPE, RAW_SCOPE);
                        when(requestValidator.validateScopes(clientDetails, null)).thenReturn(false);
                    }
                }

                @Test
                @DisplayName("설정된 Approval 페이지로 포워딩 되어야한다.")
                void shouldForwardingConfigApprovalPage() {
                    ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);

                    assertEquals("forward:" + FORWARD_PAGE, modelAndView.getViewName());
                }

                @Test
                @DisplayName("클라이언트명을 ModelAndView에 저장해야 한다.")
                void shouldSaveClientNameToModeAndView() {
                    ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);

                    assertEquals(CLIENT_NAME, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_CLIENT_NAME));
                }

                @Test
                @DisplayName("요청한 스코프의 상세 정보를 ModelAndView에 저장해야 한다.")
                void shouldSaveRequestingScopeToModelAndView() {
                    ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);

                    assertEquals(scopeDetails, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_SCOPES_NAME));
                }
            }

            @AfterEach
            void after() {
                this.model = new HashMap<>();
            }
        }
    }

    @Nested
    @DisplayName("스코프 허용 확인 엔드포인트")
    class ScopeApprovalEndpoint {

        @Nested
        @DisplayName("인증 정보가 Authentication 타입이 아닐시")
        class WhenPrincipalTypeIsNotAuthentication {

            private Map<String, String> approvalParameter;
            private Map<String, Object> model;
            private SessionStatus sessionStatus;
            private Principal principal;

            @BeforeEach
            void setup() {
                this.approvalParameter = new HashMap<>();
                this.model = new HashMap<>();
                this.sessionStatus = mock(SessionStatus.class);
                this.principal = mock(Principal.class);
            }

            @Test
            @DisplayName("InsufficientAuthenticationException이 발생해야 한다.")
            void shouldThrowsInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.approval(approvalParameter, model, sessionStatus, principal));
            }
        }

        @Nested
        @DisplayName("인증 정보의 인증 여부가 false 일시")
        class WhenAuthenticationObjectIsNotAuthenticated {
            private Map<String, String> approvalParameter;
            private Map<String, Object> model;
            private SessionStatus sessionStatus;
            private Authentication principal;

            @BeforeEach
            void setup() {
                this.approvalParameter = new HashMap<>();
                this.model = new HashMap<>();
                this.sessionStatus = mock(SessionStatus.class);
                this.principal = mock(Authentication.class);

                when(this.principal.isAuthenticated()).thenReturn(false);
            }

            @Test
            @DisplayName("InsufficientAuthenticationException이 발생해야 한다.")
            void shouldThrowsInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.approval(approvalParameter, model, sessionStatus, principal));
            }
        }

        @Nested
        @DisplayName("세션에 원본 인가 요청 정보가 없을시")
        class WhenNotHaveOriginalAuthorizationRequestInSession {
            private Map<String, String> approvalParameter;
            private Map<String, Object> model;
            private SessionStatus sessionStatus;
            private Authentication principal;

            @BeforeEach
            void setup() {
                this.approvalParameter = new HashMap<>();
                this.model = new HashMap<>();
                this.sessionStatus = mock(SessionStatus.class);
                this.principal = mock(Authentication.class);

                this.model.put(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null);

                when(this.principal.isAuthenticated()).thenReturn(true);
            }

            @Test
            @DisplayName("InvalidRequestException이 발생해야 한다.")
            void shouldThrowsInvalidRequestException() {
                assertThrows(InvalidRequestException.class, () -> endpoint.approval(approvalParameter, model, sessionStatus, principal));
            }
        }

        private Map<String, String> approvalParameter;
        private Map<String, Object> model;
        private SessionStatus sessionStatus;
        private Authentication authentication;
        private AuthorizationRequest originalAuthorizationRequest;
        private Set<String> resolvedRequestScope;

        @BeforeEach
        void setup() {
            this.approvalParameter = new HashMap<>();
            this.model = new HashMap<>();
            this.sessionStatus = mock(SessionStatus.class);
            this.authentication = mock(Authentication.class);
            this.originalAuthorizationRequest = mock(AuthorizationRequest.class);
            this.resolvedRequestScope = new HashSet<>(Arrays.asList("RESOLVED-SCOPE-1", "RESOLVED-SCOPE-2", "RESOLVED-SCOPE-3"));

            ScopeApprovalResolver resolver = mock(ScopeApprovalResolver.class);
            Set<String> originalRequestScope = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));

            this.model.put(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, originalAuthorizationRequest);

            when(authentication.isAuthenticated()).thenReturn(true);
            when(authentication.getName()).thenReturn(RAW_USERNAME);
            when(originalAuthorizationRequest.clientId()).thenReturn(RAW_CLIENT_ID);
            when(originalAuthorizationRequest.username()).thenReturn(RAW_USERNAME);
            when(originalAuthorizationRequest.redirectURI()).thenReturn(RESOLVED_REDIRECT_URI);
            when(originalAuthorizationRequest.requestScopes()).thenReturn(originalRequestScope);
            when(resolver.resolveApprovalScopes(originalAuthorizationRequest, approvalParameter)).thenReturn(resolvedRequestScope);
            when(codeGenerator.generateNewAuthorizationCode(any())).thenReturn(CODE);

            endpoint.setApprovalResolver(resolver);
        }

        @Test
        @DisplayName("원본 인가 요청에는 어떤 설정도 하지 않아야 한다.")
        void shouldNotConfigOriginalAuthorizationRequest() {
            endpoint.approval(approvalParameter, model, sessionStatus, authentication);

            verify(originalAuthorizationRequest, never()).setRequestScopes(any());
            verify(originalAuthorizationRequest, never()).setRedirectURI(any());
        }

        @Test
        @DisplayName("요청 받은 클라이언트 아이디로 새 코드를 부여해야 한다.")
        void shouldGrantNewCodeUsingRequestingClientId() {
            ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

            endpoint.approval(approvalParameter, model, sessionStatus, authentication);
            verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
            assertEquals(RAW_CLIENT_ID, requestCaptor.getValue().clientId());
        }

        @Test
        @DisplayName("요청 받은 리다이렉트 주소로 새 코드를 부여해야 한다.")
        void shouldGrantNewCodeUsingRequestingRedirectURI() {
            ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

            endpoint.approval(approvalParameter, model, sessionStatus, authentication);
            verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
            assertEquals(RESOLVED_REDIRECT_URI, requestCaptor.getValue().redirectURI());
        }

        @Test
        @DisplayName("Resolver에서 반환된 스코프로 새 코드를 부여해야 한다.")
        void shouldGrantNewCodeUsingResolvedScope() {
            ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

            endpoint.approval(approvalParameter, model, sessionStatus, authentication);
            verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
            assertEquals(resolvedRequestScope, requestCaptor.getValue().requestScopes());
        }

        @Test
        @DisplayName("요청한 리다이렉트 주소로 리다이렉트 하는 View를 설정해야 한다.")
        void shouldConfigRedirectToRequestingRedirectUriView() {
            ModelAndView modelAndView = endpoint.approval(approvalParameter, model, sessionStatus, authentication);

            assertTrue(modelAndView.getView() instanceof RedirectView);
            assertEquals(RESOLVED_REDIRECT_URI.toString(), ((RedirectView) modelAndView.getView()).getUrl());
        }

        @Test
        @DisplayName("ModelAndView에 새로 생성한 인가 코드를 저장해야 한다.")
        void shouldSaveStateTokenToModelAndView() {
            ModelAndView modelAndView = endpoint.approval(approvalParameter, model, sessionStatus, authentication);

            assertEquals(RAW_CODE, modelAndView.getModel().get(OAuth2Utils.AuthorizationResponseKey.CODE));
        }

        @Nested
        @DisplayName("요청 받은 STATE가 null이 아닐시")
        class WhenRequestingStateNotNull {

            @BeforeEach
            void setup() {
                when(originalAuthorizationRequest.state()).thenReturn(STATE);
            }

            @Test
            @DisplayName("요청 받은 STATE로 새 코드를 부여해야 한다.")
            void shouldGrantNewCodeUsingRequestingState() {
                ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

                endpoint.approval(approvalParameter, model, sessionStatus, authentication);
                verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
                assertEquals(STATE, requestCaptor.getValue().state());
            }

            @Test
            @DisplayName("ModelAndView에 요청 받은 STATE를 저장해야 한다.")
            void shouldSaveStateTokenToModelAndView() {
                ModelAndView modelAndView = endpoint.approval(approvalParameter, model, sessionStatus, authentication);

                assertEquals(STATE, modelAndView.getModel().get(OAuth2Utils.AuthorizationResponseKey.STATE));
            }
        }

        @Nested
        @DisplayName("요청 받은 STATE가 null 일시")
        class WhenRequestingStateNull {

            @BeforeEach
            void setup() {
                when(originalAuthorizationRequest.state()).thenReturn(null);
            }

            @Test
            @DisplayName("STATE는 null로 새 코드를 부여해야 한다.")
            void shouldGrantNewCodeUsingNullState() {
                ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

                endpoint.approval(approvalParameter, model, sessionStatus, authentication);
                verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
                assertNull(requestCaptor.getValue().state());
            }

            @Test
            @DisplayName("ModelAndView에 STATE를 저장하지 않아야 한다.")
            void shouldSaveStateTokenToModelAndView() {
                ModelAndView modelAndView = endpoint.approval(approvalParameter, model, sessionStatus, authentication);

                assertFalse(modelAndView.getModel().containsKey(OAuth2Utils.AuthorizationResponseKey.STATE));
            }
        }
    }

    @Nested
    @DisplayName("에외 처리")
    class ExceptionHandling {

        @Nested
        @DisplayName("리다이렉트 인증 예외 발생시")
        class WhenThrowsRedirectMismatchException {
            private RedirectMismatchException redirectMismatchException;
            private ServletWebRequest servletWebRequest;
            private HttpServletResponse servletResponse;

            private OAuth2Error oAuth2Error;

            @BeforeEach
            void setup() {
                this.oAuth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT);

                HttpServletRequest servletRequest = mock(HttpServletRequest.class);
                OAuth2ExceptionTranslator exceptionTranslator = mock(OAuth2ExceptionTranslator.class);
                ResponseEntity<OAuth2Error> oAuth2ErrorResponseEntity = new ResponseEntity<>(oAuth2Error, HttpStatus.UNAUTHORIZED);

                this.redirectMismatchException = new RedirectMismatchException("TEST");
                this.servletResponse = mock(HttpServletResponse.class);
                this.servletWebRequest = new ServletWebRequest(servletRequest, servletResponse);

                when(exceptionTranslator.translate(redirectMismatchException)).thenReturn(oAuth2ErrorResponseEntity);
                endpoint.setExceptionTranslator(exceptionTranslator);
            }

            @Test
            @DisplayName("HTTP 상태 코드는 401이어야 한다.")
            void shouldHttpStatusCode401() {
                endpoint.handleOAuth2AuthenticationException(redirectMismatchException, servletWebRequest);

                verify(servletResponse, times(1)).setStatus(401);
            }

            @Test
            @DisplayName("에러페이지로 포워딩 되어야 한다.")
            void shouldForwardingErrorPage() {
                ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(redirectMismatchException, servletWebRequest);

                assertEquals("/oauth/error", modelAndView.getViewName());
            }

            @Test
            @DisplayName("ModelAndView에 OAuth2 에러 정보를 저장해야 한다.")
            void shouldSaveOAuth2ErrorCodeToModelAndView() {
                ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(redirectMismatchException, servletWebRequest);

                assertEquals(oAuth2Error, modelAndView.getModel().get("error"));
            }
        }

        @Nested
        @DisplayName("리다이렉트 인증 예외를 제외한 OAuth2 인증 예외가 발생했을시")
        class WhenThrowsOAuth2AuthenticationExceptionExcludingRedirectMismatched {
            private OAuth2AuthenticationException authenticationException;
            private ServletWebRequest servletWebRequest;
            private HttpServletRequest servletRequest;

            private OAuth2Error oAuth2Error;

            @BeforeEach
            void setup() {
                this.oAuth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);

                HttpServletResponse servletResponse = mock(HttpServletResponse.class);
                ResponseEntity<OAuth2Error> oAuth2ErrorResponseEntity = new ResponseEntity<>(oAuth2Error, HttpStatus.UNAUTHORIZED);
                OAuth2ExceptionTranslator exceptionTranslator = mock(OAuth2ExceptionTranslator.class);

                this.authenticationException = mock(OAuth2AuthenticationException.class);
                this.servletRequest = mock(HttpServletRequest.class);
                this.servletWebRequest = new ServletWebRequest(servletRequest, servletResponse);

                when(exceptionTranslator.translate(authenticationException)).thenReturn(oAuth2ErrorResponseEntity);
                endpoint.setExceptionTranslator(exceptionTranslator);
            }

            @Nested
            @DisplayName("세션에 인가 요청 정보가 남아 있지 않을시")
            class WhenAuthorizationRequestNotRemainedInSession {
                private URI storedURI;
                private String storedClientId;

                @BeforeEach
                void setup() {
                    SessionAttributeStore sessionAttributeStore = mock(SessionAttributeStore.class);
                    this.storedURI = URI.create("http://stored.localhost:8080");
                    this.storedClientId = "STORED-CLIENT-ID";

                    when(servletRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID)).thenReturn(storedClientId);
                    when(servletRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI)).thenReturn(storedURI.toString());
                    when(sessionAttributeStore.retrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE))
                            .thenReturn(null);
                    endpoint.setSessionAttributeStore(sessionAttributeStore);
                }


                @Nested
                @DisplayName("클라이언트 정보 검색중 예외가 발생할시")
                class WhenThrowsExceptionDuringClientLookup {

                    @BeforeEach
                    void setup() {
                        when(clientDetailsService.loadClientDetailsByClientId(storedClientId))
                                .thenThrow(new OAuth2ClientRegistrationException("TEST"));
                    }

                    @Test
                    @DisplayName("에러 페이지로 포워딩 해야 한다.")
                    void shouldForwardingErrorPage() {
                        ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(authenticationException, servletWebRequest);

                        assertEquals("/oauth/error", modelAndView.getViewName());
                    }

                    @Test
                    @DisplayName("ModelAndView에 OAuth2 에러 정보를 저장해야 한다.")
                    void shouldSaveOAuth2ErrorCodeToModelAndView() {
                        ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(authenticationException, servletWebRequest);

                        assertEquals(oAuth2Error, modelAndView.getModel().get("error"));
                    }
                }

                @Nested
                @DisplayName("요청 받은 리다이렉트 주소가 유효하지 않을시")
                class WhenRequestingRedirectUriNotAllowed {

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
                        RedirectResolver redirectResolver = mock(RedirectResolver.class);

                        when(redirectResolver.resolveRedirectURI(storedURI.toString(), clientDetails))
                                .thenThrow(new RedirectMismatchException("TEST"));
                        endpoint.setRedirectResolver(redirectResolver);
                    }

                    @Test
                    @DisplayName("에러 페이지로 포워딩 해야 한다.")
                    void shouldForwardingErrorPage() {
                        ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(authenticationException, servletWebRequest);

                        assertEquals("/oauth/error", modelAndView.getViewName());
                    }

                    @Test
                    @DisplayName("ModelAndView에 OAuth2 에러 정보를 저장해야 한다.")
                    void shouldSaveOAuth2ErrorCodeToModelAndView() {
                        ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(authenticationException, servletWebRequest);

                        assertEquals(oAuth2Error, modelAndView.getModel().get("error"));
                    }
                }

                @Nested
                @DisplayName("요청 받은 리다이렉트 주소가 유효할시")
                class WhenRequestingRedirectUriAllowed {

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
                        RedirectResolver redirectResolver = mock(RedirectResolver.class);

                        when(clientDetailsService.loadClientDetailsByClientId(storedClientId)).thenReturn(clientDetails);
                        when(redirectResolver.resolveRedirectURI(storedURI.toString(), clientDetails))
                                .thenReturn(storedURI);
                        endpoint.setRedirectResolver(redirectResolver);
                    }

                    @Nested
                    @DisplayName("요청 정보에 state가 존재할시")
                    class WhenRequestingIncludeState {

                        @BeforeEach
                        void setup() {
                            when(servletRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.STATE)).thenReturn(STATE);
                        }

                        @Test
                        @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorCode() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getErrorCode(), modelAndView.getModel().get("error_code"));
                        }

                        @Test
                        @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorDescription() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getDescription(), modelAndView.getModel().get("error_description"));
                        }

                        @Test
                        @DisplayName("STATE를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithState() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(STATE, modelAndView.getModel().get("state"));
                        }
                    }

                    @Nested
                    @DisplayName("요청 정보에 state가 존재하지 않을시")
                    class WhenRequestingExcludingState {

                        @BeforeEach
                        void setup() {
                            when(servletRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.STATE)).thenReturn(null);
                        }

                        @Test
                        @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorCode() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getErrorCode(), modelAndView.getModel().get("error_code"));
                        }

                        @Test
                        @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorDescription() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getDescription(), modelAndView.getModel().get("error_description"));
                        }

                        @Test
                        @DisplayName("STATE를 매개변수에서 제외하고 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithState() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertNull(modelAndView.getModel().get("state"));
                        }
                    }
                }
            }

            @Nested
            @DisplayName("세션에 인가 요청 정보가 남아 있을시")
            class WhenAuthorizationRequestRemainedInSession {

                private AuthorizationRequest authorizationRequest;
                private URI storedURI;
                private String storedClientId;

                @BeforeEach
                void setup() {
                    SessionAttributeStore sessionAttributeStore = mock(SessionAttributeStore.class);
                    this.authorizationRequest = mock(AuthorizationRequest.class);
                    this.storedURI = URI.create("http://stored.localhost:8080");
                    this.storedClientId = "STORED-CLIENT-ID";

                    when(authorizationRequest.clientId()).thenReturn(storedClientId);
                    when(authorizationRequest.redirectURI()).thenReturn(storedURI);
                    when(sessionAttributeStore.retrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE))
                            .thenReturn(authorizationRequest);

                    endpoint.setSessionAttributeStore(sessionAttributeStore);
                }

                @Nested
                @DisplayName("클라이언트 정보 검색중 예외가 발생할시")
                class WhenThrowsExceptionDuringClientLookup {

                    @BeforeEach
                    void setup() {
                        when(clientDetailsService.loadClientDetailsByClientId(storedClientId))
                                .thenThrow(new OAuth2ClientRegistrationException("TEST"));
                    }

                    @Test
                    @DisplayName("에러 페이지로 포워딩 해야 한다.")
                    void shouldForwardingErrorPage() {
                        ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(authenticationException, servletWebRequest);

                        assertEquals("/oauth/error", modelAndView.getViewName());
                    }

                    @Test
                    @DisplayName("ModelAndView에 OAuth2 에러 정보를 저장해야 한다.")
                    void shouldSaveOAuth2ErrorCodeToModelAndView() {
                        ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(authenticationException, servletWebRequest);

                        assertEquals(oAuth2Error, modelAndView.getModel().get("error"));
                    }
                }

                @Nested
                @DisplayName("요청 받은 리다이렉트 주소가 유효하지 않을시")
                class WhenRequestingRedirectUriNotAllowed {

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
                        RedirectResolver redirectResolver = mock(RedirectResolver.class);

                        when(redirectResolver.resolveRedirectURI(storedURI.toString(), clientDetails))
                                .thenThrow(new RedirectMismatchException("TEST"));
                        endpoint.setRedirectResolver(redirectResolver);
                    }

                    @Test
                    @DisplayName("에러 페이지로 포워딩 해야 한다.")
                    void shouldForwardingErrorPage() {
                        ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(authenticationException, servletWebRequest);

                        assertEquals("/oauth/error", modelAndView.getViewName());
                    }

                    @Test
                    @DisplayName("ModelAndView에 OAuth2 에러 정보를 저장해야 한다.")
                    void shouldSaveOAuth2ErrorCodeToModelAndView() {
                        ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(authenticationException, servletWebRequest);

                        assertEquals(oAuth2Error, modelAndView.getModel().get("error"));
                    }
                }

                @Nested
                @DisplayName("요청 받은 리다이렉트 주소가 유효할시")
                class WhenRequestingRedirectUriAllowed {

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
                        RedirectResolver redirectResolver = mock(RedirectResolver.class);

                        when(clientDetailsService.loadClientDetailsByClientId(storedClientId)).thenReturn(clientDetails);
                        when(redirectResolver.resolveRedirectURI(storedURI.toString(), clientDetails))
                                .thenReturn(storedURI);
                        endpoint.setRedirectResolver(redirectResolver);
                    }

                    @Nested
                    @DisplayName("요청 정보에 state가 존재할시")
                    class WhenRequestingIncludeState {

                        @BeforeEach
                        void setup() {
                            when(authorizationRequest.state()).thenReturn(STATE);
                        }

                        @Test
                        @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorCode() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getErrorCode(), modelAndView.getModel().get("error_code"));
                        }

                        @Test
                        @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorDescription() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getDescription(), modelAndView.getModel().get("error_description"));
                        }

                        @Test
                        @DisplayName("STATE를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithState() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(STATE, modelAndView.getModel().get("state"));
                        }
                    }

                    @Nested
                    @DisplayName("요청 정보에 state가 존재하지 않을시")
                    class WhenRequestingExcludingState {

                        @BeforeEach
                        void setup() {
                            when(authorizationRequest.state()).thenReturn(null);
                        }

                        @Test
                        @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorCode() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getErrorCode(), modelAndView.getModel().get("error_code"));
                        }

                        @Test
                        @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorDescription() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getDescription(), modelAndView.getModel().get("error_description"));
                        }

                        @Test
                        @DisplayName("STATE를 매개변수에서 제외하고 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithState() {
                            ModelAndView modelAndView = endpoint.handleOtherException(authenticationException, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertNull(modelAndView.getModel().get("state"));
                        }
                    }
                }
            }
        }

        @Nested
        @DisplayName("OAuth 클라이언트 인증 예외 발생시")
        class WhenThrowsClientAuthenticationException {
            private OAuth2ClientRegistrationException clientRegistrationException;
            private ServletWebRequest servletWebRequest;
            private HttpServletResponse servletResponse;

            private OAuth2Error oAuth2Error;

            @BeforeEach
            void setup() {
                this.oAuth2Error = new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);

                HttpServletRequest servletRequest = mock(HttpServletRequest.class);
                OAuth2ExceptionTranslator exceptionTranslator = mock(OAuth2ExceptionTranslator.class);
                ResponseEntity<OAuth2Error> oAuth2ErrorResponseEntity = new ResponseEntity<>(oAuth2Error, HttpStatus.UNAUTHORIZED);

                this.clientRegistrationException = new OAuth2ClientRegistrationException("TEST");
                this.servletResponse = mock(HttpServletResponse.class);
                this.servletWebRequest = new ServletWebRequest(servletRequest, servletResponse);

                when(exceptionTranslator.translate(clientRegistrationException)).thenReturn(oAuth2ErrorResponseEntity);
                endpoint.setExceptionTranslator(exceptionTranslator);
            }

            @Test
            @DisplayName("HTTP 상태 코드는 401이어야 한다.")
            void shouldHttpStatusCode401() {
                endpoint.handleClientRegistrationException(clientRegistrationException, servletWebRequest);

                verify(servletResponse, times(1)).setStatus(401);
            }

            @Test
            @DisplayName("에러페이지로 포워딩 되어야 한다.")
            void shouldForwardingErrorPage() {
                ModelAndView modelAndView = endpoint.handleClientRegistrationException(clientRegistrationException, servletWebRequest);

                assertEquals("/oauth/error", modelAndView.getViewName());
            }

            @Test
            @DisplayName("ModelAndView에 OAuth2 에러 정보를 저장해야 한다.")
            void shouldSaveOAuth2ErrorCodeToModelAndView() {
                ModelAndView modelAndView = endpoint.handleClientRegistrationException(clientRegistrationException, servletWebRequest);

                assertEquals(oAuth2Error, modelAndView.getModel().get("error"));
            }
        }

        @Nested
        @DisplayName("예상하지 못한 예외 발생했을시")
        class WhenThrowsUnexpectedException {
            private Exception exception;
            private ServletWebRequest servletWebRequest;
            private HttpServletRequest servletRequest;

            private OAuth2Error oAuth2Error;

            @BeforeEach
            void setup() {
                this.oAuth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "TEST", null);

                HttpServletResponse servletResponse = mock(HttpServletResponse.class);
                ResponseEntity<OAuth2Error> oAuth2ErrorResponseEntity = new ResponseEntity<>(oAuth2Error, HttpStatus.UNAUTHORIZED);
                OAuth2ExceptionTranslator exceptionTranslator = mock(OAuth2ExceptionTranslator.class);

                this.exception = mock(Exception.class);
                this.servletRequest = mock(HttpServletRequest.class);
                this.servletWebRequest = new ServletWebRequest(servletRequest, servletResponse);

                when(exceptionTranslator.translate(exception)).thenReturn(oAuth2ErrorResponseEntity);
                endpoint.setExceptionTranslator(exceptionTranslator);
            }

            @Nested
            @DisplayName("세션에 인가 요청 정보가 남아 있지 않을시")
            class WhenAuthorizationRequestNotRemainedInSession {
                private URI storedURI;
                private String storedClientId;

                @BeforeEach
                void setup() {
                    SessionAttributeStore sessionAttributeStore = mock(SessionAttributeStore.class);
                    this.storedURI = URI.create("http://stored.localhost:8080");
                    this.storedClientId = "STORED-CLIENT-ID";

                    when(servletRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID)).thenReturn(storedClientId);
                    when(servletRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI)).thenReturn(storedURI.toString());
                    when(sessionAttributeStore.retrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE))
                            .thenReturn(null);
                    endpoint.setSessionAttributeStore(sessionAttributeStore);
                }


                @Nested
                @DisplayName("클라이언트 정보 검색중 예외가 발생할시")
                class WhenThrowsExceptionDuringClientLookup {

                    @BeforeEach
                    void setup() {
                        when(clientDetailsService.loadClientDetailsByClientId(storedClientId))
                                .thenThrow(new OAuth2ClientRegistrationException("TEST"));
                    }

                    @Test
                    @DisplayName("에러 페이지로 포워딩 해야 한다.")
                    void shouldForwardingErrorPage() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertEquals("/oauth/error", modelAndView.getViewName());
                    }

                    @Test
                    @DisplayName("ModelAndView에 OAuth2 에러 정보를 저장해야 한다.")
                    void shouldSaveOAuth2ErrorCodeToModelAndView() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertEquals(oAuth2Error, modelAndView.getModel().get("error"));
                    }
                }

                @Nested
                @DisplayName("요청 받은 리다이렉트 주소가 유효하지 않을시")
                class WhenRequestingRedirectUriNotAllowed {

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
                        RedirectResolver redirectResolver = mock(RedirectResolver.class);

                        when(redirectResolver.resolveRedirectURI(storedURI.toString(), clientDetails))
                                .thenThrow(new RedirectMismatchException("TEST"));
                        endpoint.setRedirectResolver(redirectResolver);
                    }

                    @Test
                    @DisplayName("에러 페이지로 포워딩 해야 한다.")
                    void shouldForwardingErrorPage() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertEquals("/oauth/error", modelAndView.getViewName());
                    }

                    @Test
                    @DisplayName("ModelAndView에 OAuth2 에러 정보를 저장해야 한다.")
                    void shouldSaveOAuth2ErrorCodeToModelAndView() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertEquals(oAuth2Error, modelAndView.getModel().get("error"));
                    }
                }

                @Nested
                @DisplayName("요청 받은 리다이렉트 주소가 유효할시")
                class WhenRequestingRedirectUriAllowed {

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
                        RedirectResolver redirectResolver = mock(RedirectResolver.class);

                        when(clientDetailsService.loadClientDetailsByClientId(storedClientId)).thenReturn(clientDetails);
                        when(redirectResolver.resolveRedirectURI(storedURI.toString(), clientDetails))
                                .thenReturn(storedURI);
                        endpoint.setRedirectResolver(redirectResolver);
                    }

                    @Nested
                    @DisplayName("요청 정보에 state가 존재할시")
                    class WhenRequestingIncludeState {

                        @BeforeEach
                        void setup() {
                            when(servletRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.STATE)).thenReturn(STATE);
                        }

                        @Test
                        @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorCode() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getErrorCode(), modelAndView.getModel().get("error_code"));
                        }

                        @Test
                        @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorDescription() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getDescription(), modelAndView.getModel().get("error_description"));
                        }

                        @Test
                        @DisplayName("STATE를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithState() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(STATE, modelAndView.getModel().get("state"));
                        }
                    }

                    @Nested
                    @DisplayName("요청 정보에 state가 존재하지 않을시")
                    class WhenRequestingExcludingState {

                        @BeforeEach
                        void setup() {
                            when(servletRequest.getParameter(OAuth2Utils.AuthorizationRequestKey.STATE)).thenReturn(null);
                        }

                        @Test
                        @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorCode() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getErrorCode(), modelAndView.getModel().get("error_code"));
                        }

                        @Test
                        @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorDescription() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getDescription(), modelAndView.getModel().get("error_description"));
                        }

                        @Test
                        @DisplayName("STATE를 매개변수에서 제외하고 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithState() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertNull(modelAndView.getModel().get("state"));
                        }
                    }
                }
            }

            @Nested
            @DisplayName("세션에 인가 요청 정보가 남아 있을시")
            class WhenAuthorizationRequestRemainedInSession {

                private AuthorizationRequest authorizationRequest;
                private URI storedURI;
                private String storedClientId;

                @BeforeEach
                void setup() {
                    this.authorizationRequest = mock(AuthorizationRequest.class);
                    SessionAttributeStore sessionAttributeStore = mock(SessionAttributeStore.class);
                    this.storedURI = URI.create("http://stored.localhost:8080");
                    this.storedClientId = "STORED-CLIENT-ID";

                    when(authorizationRequest.clientId()).thenReturn(storedClientId);
                    when(authorizationRequest.redirectURI()).thenReturn(storedURI);
                    when(sessionAttributeStore.retrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE))
                            .thenReturn(authorizationRequest);

                    endpoint.setSessionAttributeStore(sessionAttributeStore);
                }

                @Nested
                @DisplayName("클라이언트 정보 검색중 예외가 발생할시")
                class WhenThrowsExceptionDuringClientLookup {

                    @BeforeEach
                    void setup() {
                        when(clientDetailsService.loadClientDetailsByClientId(storedClientId))
                                .thenThrow(new OAuth2ClientRegistrationException("TEST"));
                    }

                    @Test
                    @DisplayName("에러 페이지로 포워딩 해야 한다.")
                    void shouldForwardingErrorPage() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertEquals("/oauth/error", modelAndView.getViewName());
                    }

                    @Test
                    @DisplayName("ModelAndView에 OAuth2 에러 정보를 저장해야 한다.")
                    void shouldSaveOAuth2ErrorCodeToModelAndView() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertEquals(oAuth2Error, modelAndView.getModel().get("error"));
                    }
                }

                @Nested
                @DisplayName("요청 받은 리다이렉트 주소가 유효하지 않을시")
                class WhenRequestingRedirectUriNotAllowed {

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
                        RedirectResolver redirectResolver = mock(RedirectResolver.class);

                        when(redirectResolver.resolveRedirectURI(storedURI.toString(), clientDetails))
                                .thenThrow(new RedirectMismatchException("TEST"));
                        endpoint.setRedirectResolver(redirectResolver);
                    }

                    @Test
                    @DisplayName("에러 페이지로 포워딩 해야 한다.")
                    void shouldForwardingErrorPage() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertEquals("/oauth/error", modelAndView.getViewName());
                    }

                    @Test
                    @DisplayName("ModelAndView에 OAuth2 에러 정보를 저장해야 한다.")
                    void shouldSaveOAuth2ErrorCodeToModelAndView() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertEquals(oAuth2Error, modelAndView.getModel().get("error"));
                    }
                }

                @Nested
                @DisplayName("요청 받은 리다이렉트 주소가 유효할시")
                class WhenRequestingRedirectUriAllowed {

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
                        RedirectResolver redirectResolver = mock(RedirectResolver.class);

                        when(clientDetailsService.loadClientDetailsByClientId(storedClientId)).thenReturn(clientDetails);
                        when(redirectResolver.resolveRedirectURI(storedURI.toString(), clientDetails))
                                .thenReturn(storedURI);
                        endpoint.setRedirectResolver(redirectResolver);
                    }

                    @Nested
                    @DisplayName("요청 정보에 state가 존재할시")
                    class WhenRequestingIncludeState {

                        @BeforeEach
                        void setup() {
                            when(authorizationRequest.state()).thenReturn(STATE);
                        }

                        @Test
                        @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorCode() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getErrorCode(), modelAndView.getModel().get("error_code"));
                        }

                        @Test
                        @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorDescription() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getDescription(), modelAndView.getModel().get("error_description"));
                        }

                        @Test
                        @DisplayName("STATE를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithState() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(STATE, modelAndView.getModel().get("state"));
                        }
                    }

                    @Nested
                    @DisplayName("요청 정보에 state가 존재하지 않을시")
                    class WhenRequestingExcludingState {

                        @BeforeEach
                        void setup() {
                            when(authorizationRequest.state()).thenReturn(null);
                        }

                        @Test
                        @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorCode() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getErrorCode(), modelAndView.getModel().get("error_code"));
                        }

                        @Test
                        @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithErrorDescription() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertEquals(oAuth2Error.getDescription(), modelAndView.getModel().get("error_description"));
                        }

                        @Test
                        @DisplayName("STATE를 매개변수에서 제외하고 리다이렉트 주소로 리다이렉트 해야 한다.")
                        void shouldRedirectWithState() {
                            ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                            assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                            assertNull(modelAndView.getModel().get("state"));
                        }
                    }
                }
            }
        }
    }

}
