package cube8540.oauth.authentication.credentials.oauth.authorize.endpoint;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.error.RedirectMismatchException;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AuthorizationCodeGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.CLIENT_NAME;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.CLIENT_SCOPE;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.CLIENT_SCOPE_DETAILS;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.FORWARD_PAGE;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.INVALID_GRANT_ERROR;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.INVALID_GRANT_RESPONSE;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.INVALID_REQUEST_ERROR;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.INVALID_REQUEST_RESPONSE;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.RAW_AUTHORIZATION_CODE;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.RAW_REDIRECT_URI;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.RAW_RESOLVED_REDIRECT_URI;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.RAW_RESOLVED_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.RESOLVED_REDIRECT_URI;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.SCOPE;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.SCOPE_DETAILS;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.STATE;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.UNAUTHORIZED_CLIENT_ERROR;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.UNAUTHORIZED_CLIENT_RESPONSE;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockAuthorizationRequest;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockAuthorizationRequestMap;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockAuthorizedAuthentication;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockClientDetailsService;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockCodeGenerator;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockExceptionTranslator;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockHttpServletRequest;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockNotAuthorizedAuthentication;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockRedirectResolver;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockRequestValidator;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockScopeApprovalResolver;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockScopeDetailsService;
import static cube8540.oauth.authentication.credentials.oauth.authorize.endpoint.AuthorizationEndpointTestHelper.mockSessionAttributeStore;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("인가 엔드포인트 테스트")
class AuthorizationEndpointTest {

    @Nested
    @DisplayName("인가")
    class Authorize {

        @Nested
        @DisplayName("인증 정보가 Authentication 타입이 아닐시")
        class WhenPrincipalTypeIsNotAuthentication {
            private Map<String, String> parameter;
            private Map<String, Object> model;
            private Principal principal;
            private AuthorizationEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.parameter = mockAuthorizationRequestMap().build();
                this.model = new HashMap<>();
                this.principal = mock(Principal.class);
                this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), mockCodeGenerator().build());
            }

            @Test
            @DisplayName("InsufficientAuthenticationException 이 발생해야 한다.")
            void shouldThrowsInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.authorize(parameter, model, principal));
            }
        }

        @Nested
        @DisplayName("인증 정보의 인증 여부가 false 일시")
        class WhenAuthenticationObjectIsNotAuthenticated {
            private Map<String, String> parameter;
            private Map<String, Object> model;
            private Principal principal;
            private AuthorizationEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.parameter = mockAuthorizationRequestMap().build();
                this.model = new HashMap<>();
                this.principal = mockNotAuthorizedAuthentication();
                this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), mockCodeGenerator().build());
            }

            @Test
            @DisplayName("InsufficientAuthenticationException 이 발생해야 한다.")
            void shouldThrowsInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.authorize(parameter, model, principal));
            }
        }

        @Nested
        @DisplayName("유저 인증을 완료한 요청일시")
        class WhenAuthenticationCompletedRequesting {

            @Nested
            @DisplayName("요청 받은 응답 타입이 null 일시")
            class WhenRequestingResponseTypeIsNull {
                private Map<String, String> parameter;
                private Map<String, Object> model;
                private Principal principal;
                private AuthorizationEndpoint endpoint;

                @BeforeEach
                void setup() {
                    this.parameter = mockAuthorizationRequestMap().configDefault().configResponseType(null).build();
                    this.model = new HashMap<>();
                    this.principal = mockAuthorizedAuthentication();
                    this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), mockCodeGenerator().build());
                }

                @Test
                @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 INVALID_REQUEST 이어야 한다.")
                void shouldThrowsUnsupportedResponseTypeExceptionAndErrorCodeIsInvalidRequest() {
                    OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.authorize(parameter, model, principal))
                            .getError();

                    assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
                }
            }

            @Nested
            @DisplayName("요청 받은 응답 타입이 code 가 아닐시")
            class WhenRequestingResponseTypeIsNotCode {
                private Map<String, String> parameter;
                private Map<String, Object> model;
                private Principal principal;
                private AuthorizationEndpoint endpoint;

                @BeforeEach
                void setup() {
                    this.parameter = mockAuthorizationRequestMap().configDefault().configResponseType("token").build();
                    this.model = new HashMap<>();
                    this.principal = mockAuthorizedAuthentication();
                    this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), mockCodeGenerator().build());
                }

                @Test
                @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 UNSUPPORTED_RESPONSE_TYPE 이어야 한다.")
                void shouldThrowsUnsupportedResponseTypeExceptionAndErrorCodeIsUnsupportedResponseType() {
                    OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.authorize(parameter, model, principal))
                            .getError();

                    assertEquals(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, error.getErrorCode());
                }
            }

            @Nested
            @DisplayName("요청 받은 응답 타입이 code 일시")
            class WhenRequestingResponseTypeIsCode {

                @Nested
                @DisplayName("요청한 스코프가 유효하지 않을시")
                class WhenRequestingScopeIsNotAllowed {
                    private Map<String, String> parameter;
                    private Map<String, Object> model;
                    private Principal principal;
                    private AuthorizationEndpoint endpoint;

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mockClientDetails().configDefault().build();
                        OAuth2ClientDetailsService clientDetailsService = mockClientDetailsService().registerClient(clientDetails).build();
                        RedirectResolver redirectResolver = mockRedirectResolver().configResolve(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI).build();
                        OAuth2RequestValidator requestValidator = mockRequestValidator().configNotAllowedScopes(clientDetails, SCOPE).build();

                        this.parameter = mockAuthorizationRequestMap().configDefault().build();
                        this.model = new HashMap<>();
                        this.principal = mockAuthorizedAuthentication();
                        this.endpoint = new AuthorizationEndpoint(clientDetailsService, mockScopeDetailsService().build(), mockCodeGenerator().build());
                        this.endpoint.setRedirectResolver(redirectResolver);
                        this.endpoint.setRequestValidator(requestValidator);
                    }

                    @Test
                    @DisplayName("InvalidGrantException 이 발생해야 하며 에러 코드는 INVALID_SCOPE 이어야 한다.")
                    void shouldThrowsInvalidGrantException() {
                        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> endpoint.authorize(parameter, model, principal))
                                .getError();
                        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
                    }
                }

                @Nested
                @DisplayName("요청한 스코프가 null 일시")
                class WhenRequestingScopeIsNull extends AuthorizationRequestEndpointAssertSetup {

                    @Override
                    protected void configRequestMap(AuthorizationEndpointTestHelper.MockAuthorizationRequestMap requestMap) {
                        requestMap.configScopeNull();
                    }

                    @Test
                    @DisplayName("클라이언트에 저장된 스코프를 세션에 저장해야 한다.")
                    void shouldSaveClientScopeToSession() {
                        endpoint.authorize(parameter, model, principal);

                        AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                        assertEquals(CLIENT_SCOPE, storedRequest.getRequestScopes());
                    }

                    @Test
                    @DisplayName("클라이언트에 저장된 스코프를 ModelAndView 에 저장해야 한다.")
                    void shouldSaveClientScopeToModelAndView() {
                        ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);

                        assertEquals(CLIENT_SCOPE_DETAILS, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_SCOPES_NAME));
                    }
                }

                @Nested
                @DisplayName("요청한 스코프가 null 이 아닐시")
                class WhenRequestingScopeIsNotNull extends AuthorizationRequestEndpointAssertSetup {

                    @Test
                    @DisplayName("요청 받은 스코프를 세션에 저장해야 한다.")
                    void shouldSaveRequestingScopeToSession() {
                        endpoint.authorize(parameter, model, principal);

                        AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                        assertEquals(SCOPE, storedRequest.getRequestScopes());
                    }

                    @Test
                    @DisplayName("요청 받은 스코프를 ModelAndView 에 저장해야 한다.")
                    void shouldSaveRequestingScopeToModelAndView() {
                        ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);

                        assertEquals(SCOPE_DETAILS, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_SCOPES_NAME));
                    }
                }
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
            private AuthorizationEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.approvalParameter = new HashMap<>();
                this.model = new HashMap<>();
                this.sessionStatus = mock(SessionStatus.class);
                this.principal = mock(Principal.class);
                this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), mockCodeGenerator().build());
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
            private AuthorizationEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.approvalParameter = new HashMap<>();
                this.model = new HashMap<>();
                this.sessionStatus = mock(SessionStatus.class);
                this.principal = mockNotAuthorizedAuthentication();
                this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), mockCodeGenerator().build());
            }

            @Test
            @DisplayName("InsufficientAuthenticationException 이 발생해야 한다.")
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
            private AuthorizationEndpoint endpoint;

            @BeforeEach
            void setup() {
                Map<String, String> originalAuthorizationMap = new HashMap<>();

                this.approvalParameter = new HashMap<>();
                this.model = new HashMap<>();
                this.sessionStatus = mock(SessionStatus.class);
                this.principal = mockAuthorizedAuthentication();
                this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), mockCodeGenerator().build());

                this.model.put(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null);
                this.model.put(AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE, originalAuthorizationMap);
            }

            @Test
            @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 INVALID_REQUIEST 이어야 한다.")
            void shouldThrowsInvalidRequestException() {
                OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.approval(approvalParameter, model, sessionStatus, principal))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("세션에 원본 인가 요청 매개변수 정보가 없을시")
        class WhenNotOriginalAuthorizationRequestInSession {
            private Map<String, String> approvalParameter;
            private Map<String, Object> model;
            private SessionStatus sessionStatus;
            private Authentication principal;
            private AuthorizationEndpoint endpoint;

            @BeforeEach
            void setup() {
                AuthorizationRequest originalAuthorizationRequest = mock(AuthorizationRequest.class);

                this.approvalParameter = new HashMap<>();
                this.model = new HashMap<>();
                this.sessionStatus = mock(SessionStatus.class);
                this.principal = mockAuthorizedAuthentication();
                this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), mockCodeGenerator().build());

                this.model.put(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, originalAuthorizationRequest);
                this.model.put(AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE, null);
            }

            @Test
            @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 INVALID_REQUEST 이어야 한다.")
            void shouldThrowsInvalidRequestException() {
                OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.approval(approvalParameter, model, sessionStatus, principal))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("원본 요청 매개변수에 리다이렉트 주소가 없을시")
        class WhenOriginalAuthorizationRequestMapHasNotRedirectUri extends AuthorizationSuccessAssertSetup {

            @Override
            protected void configOriginalAuthorizationRequestMap(Map<String, String> originalRequestMap) {
                originalAuthorizationRequestMap.put(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI, null);
            }

            @Test
            @DisplayName("리다이렉트 주소를 null 로 새 코드를 부여해야 한다.")
            void shouldGrantNewCodeUsingNullRedirectUri() {
                ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

                endpoint.approval(approvalParameter, model, sessionStatus, authentication);
                verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
                assertNull(requestCaptor.getValue().getRedirectUri());
            }
        }

        @Nested
        @DisplayName("원본 요청 매개변수에 리다이렉트 주소가 있을시")
        class WhenOriginalAuthorizationRequestMapHasRedirectUri extends AuthorizationSuccessAssertSetup {

            @Override
            protected void configOriginalAuthorizationRequestMap(Map<String, String> originalRequestMap) {
                originalAuthorizationRequestMap.put(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI, RESOLVED_REDIRECT_URI.toString());
            }

            @Test
            @DisplayName("요청 받은 리다이렉트 주소로 새 코드를 부여해야 한다.")
            void shouldGrantNewCodeUsingRequestingRedirectURI() {
                ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

                endpoint.approval(approvalParameter, model, sessionStatus, authentication);
                verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
                assertEquals(RESOLVED_REDIRECT_URI, requestCaptor.getValue().getRedirectUri());
            }
        }

        @Nested
        @DisplayName("요청 받은 STATE 가 null 이 아닐시")
        class WhenRequestingStateNotNull extends AuthorizationSuccessAssertSetup {

            @Override
            protected void configOriginalAuthorizationRequest(AuthorizationEndpointTestHelper.MockAuthorizationRequest request) {
                request.configState();
            }

            @Test
            @DisplayName("요청 받은 STATE 로 새 코드를 부여해야 한다.")
            void shouldGrantNewCodeUsingRequestingState() {
                ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

                endpoint.approval(approvalParameter, model, sessionStatus, authentication);
                verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
                assertEquals(STATE, requestCaptor.getValue().getState());
            }

            @Test
            @DisplayName("ModelAndView 에 요청 받은 STATE 를 저장해야 한다.")
            void shouldSaveStateTokenToModelAndView() {
                ModelAndView modelAndView = endpoint.approval(approvalParameter, model, sessionStatus, authentication);

                assertEquals(STATE, modelAndView.getModel().get(OAuth2Utils.AuthorizationResponseKey.STATE));
            }
        }

        @Nested
        @DisplayName("요청 받은 STATE 가 null 일시")
        class WhenRequestingStateNull extends AuthorizationSuccessAssertSetup {

            @Override
            protected void configOriginalAuthorizationRequest(AuthorizationEndpointTestHelper.MockAuthorizationRequest request) {
                request.configNullState();
            }

            @Test
            @DisplayName("STATE 는 null 로 새 코드를 부여해야 한다.")
            void shouldGrantNewCodeUsingNullState() {
                ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

                endpoint.approval(approvalParameter, model, sessionStatus, authentication);
                verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
                assertNull(requestCaptor.getValue().getState());
            }

            @Test
            @DisplayName("ModelAndView 에 STATE 를 저장하지 않아야 한다.")
            void shouldSaveStateTokenToModelAndView() {
                ModelAndView modelAndView = endpoint.approval(approvalParameter, model, sessionStatus, authentication);

                assertFalse(modelAndView.getModel().containsKey(OAuth2Utils.AuthorizationResponseKey.STATE));
            }
        }
    }

    @Nested
    @DisplayName("리다이렉트 인증 예외 발생시")
    class WhenThrowsRedirectMismatchException {
        private RedirectMismatchException redirectMismatchException;
        private ServletWebRequest servletWebRequest;
        private HttpServletResponse servletResponse;
        private AuthorizationEndpoint endpoint;

        @BeforeEach
        void setup() {
            this.redirectMismatchException = new RedirectMismatchException("TEST");
            this.servletResponse = mock(HttpServletResponse.class);
            this.servletWebRequest = new ServletWebRequest(mock(HttpServletRequest.class), servletResponse);
            this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), mockCodeGenerator().build());

            OAuth2ExceptionTranslator exceptionTranslator = mockExceptionTranslator().configTranslate(redirectMismatchException, INVALID_GRANT_RESPONSE).build();
            this.endpoint.setExceptionTranslator(exceptionTranslator);
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
        @DisplayName("ModelAndView 에 OAuth2 에러 정보를 저장해야 한다.")
        void shouldSaveOAuth2ErrorCodeToModelAndView() {
            ModelAndView modelAndView = endpoint.handleOAuth2AuthenticationException(redirectMismatchException, servletWebRequest);

            assertEquals(INVALID_GRANT_ERROR, modelAndView.getModel().get("error"));
        }
    }

    @Nested
    @DisplayName("OAuth 클라이언트 인증 예외 발생시")
    class WhenThrowsClientAuthenticationException {
        private ClientNotFoundException clientRegistrationException;
        private ServletWebRequest servletWebRequest;
        private HttpServletResponse servletResponse;
        private AuthorizationEndpoint endpoint;

        @BeforeEach
        void setup() {
            this.clientRegistrationException = new ClientNotFoundException("TEST");
            this.servletResponse = mock(HttpServletResponse.class);
            this.servletWebRequest = new ServletWebRequest(mock(HttpServletRequest.class), servletResponse);
            this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), mockCodeGenerator().build());

            OAuth2ExceptionTranslator exceptionTranslator = mockExceptionTranslator().configTranslate(clientRegistrationException, UNAUTHORIZED_CLIENT_RESPONSE).build();
            this.endpoint.setExceptionTranslator(exceptionTranslator);
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
        @DisplayName("ModelAndView 에 OAuth2 에러 정보를 저장해야 한다.")
        void shouldSaveOAuth2ErrorCodeToModelAndView() {
            ModelAndView modelAndView = endpoint.handleClientRegistrationException(clientRegistrationException, servletWebRequest);

            assertEquals(UNAUTHORIZED_CLIENT_ERROR, modelAndView.getModel().get("error"));
        }
    }

    @Nested
    @DisplayName("예상하지 못한 예외 발생했을시")
    class WhenThrowsUnexpectedException {

        @Nested
        @DisplayName("세션에 인가 요청 정보가 남아 있지 않을시")
        class WhenAuthorizationRequestNotRemainedInSession {

            @Nested
            @DisplayName("클라이언트 정보 검색중 예외가 발생할시")
            class WhenThrowsExceptionDuringClientLookup {
                private Exception exception;
                private ServletWebRequest servletWebRequest;
                private AuthorizationEndpoint endpoint;

                @BeforeEach
                void setup() {
                    OAuth2ClientDetailsService clientDetailsService = mockClientDetailsService().emptyClient().build();
                    HttpServletRequest servletRequest = mockHttpServletRequest().configDefault().build();

                    this.exception = new Exception("TEST");
                    this.servletWebRequest = new ServletWebRequest(servletRequest, mock(HttpServletResponse.class));

                    this.endpoint = new AuthorizationEndpoint(clientDetailsService, mockScopeDetailsService().build(), mockCodeGenerator().build());
                    this.endpoint.setSessionAttributeStore(mockSessionAttributeStore().configRetrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null).build());
                    this.endpoint.setExceptionTranslator(mockExceptionTranslator().configTranslate(exception, INVALID_REQUEST_RESPONSE).build());
                }

                @Test
                @DisplayName("에러 페이지로 포워딩 해야 한다.")
                void shouldForwardingErrorPage() {
                    ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                    assertEquals("/oauth/error", modelAndView.getViewName());
                }

                @Test
                @DisplayName("ModelAndView 에 OAuth2 에러 정보를 저장해야 한다.")
                void shouldSaveOAuth2ErrorCodeToModelAndView() {
                    ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                    assertEquals(INVALID_REQUEST_ERROR, modelAndView.getModel().get("error"));
                }
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 주소가 유효하지 않을시")
            class WhenRequestingRedirectUriNotAllowed {
                private Exception exception;
                private ServletWebRequest servletWebRequest;
                private AuthorizationEndpoint endpoint;

                @BeforeEach
                void setup() {
                    OAuth2ClientDetails clientDetails = mockClientDetails().configDefault().build();
                    OAuth2ClientDetailsService clientDetailsService = mockClientDetailsService().registerClient(clientDetails).build();
                    HttpServletRequest servletRequest = mockHttpServletRequest().configDefault().build();

                    this.exception = new Exception("TEST");
                    this.servletWebRequest = new ServletWebRequest(servletRequest, mock(HttpServletResponse.class));

                    this.endpoint = new AuthorizationEndpoint(clientDetailsService, mockScopeDetailsService().build(), mockCodeGenerator().build());
                    this.endpoint.setRedirectResolver(mockRedirectResolver().configMismatched(clientDetails, RAW_REDIRECT_URI).build());
                    this.endpoint.setSessionAttributeStore(mockSessionAttributeStore().configRetrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null).build());
                    this.endpoint.setExceptionTranslator(mockExceptionTranslator().configTranslate(exception, INVALID_REQUEST_RESPONSE).build());
                }

                @Test
                @DisplayName("에러 페이지로 포워딩 해야 한다.")
                void shouldForwardingErrorPage() {
                    ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                    assertEquals("/oauth/error", modelAndView.getViewName());
                }

                @Test
                @DisplayName("ModelAndView 에 OAuth2 에러 정보를 저장해야 한다.")
                void shouldSaveOAuth2ErrorCodeToModelAndView() {
                    ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                    assertEquals(INVALID_REQUEST_ERROR, modelAndView.getModel().get("error"));
                }
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 주소가 유효할시")
            class WhenRequestingRedirectUriAllowed {

                @Nested
                @DisplayName("요청 정보에 state 가 존재할시")
                class WhenRequestingIncludeState {
                    private Exception exception;
                    private ServletWebRequest servletWebRequest;
                    private AuthorizationEndpoint endpoint;

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mockClientDetails().configDefault().build();
                        OAuth2ClientDetailsService clientDetailsService = mockClientDetailsService().registerClient(clientDetails).build();
                        HttpServletRequest servletRequest = mockHttpServletRequest().configDefault().configState().build();

                        this.exception = new Exception("TEST");
                        this.servletWebRequest = new ServletWebRequest(servletRequest, mock(HttpServletResponse.class));

                        this.endpoint = new AuthorizationEndpoint(clientDetailsService, mockScopeDetailsService().build(), mockCodeGenerator().build());
                        this.endpoint.setRedirectResolver(mockRedirectResolver().configResolve(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI).build());
                        this.endpoint.setSessionAttributeStore(mockSessionAttributeStore().configRetrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null).build());
                        this.endpoint.setExceptionTranslator(mockExceptionTranslator().configTranslate(exception, INVALID_REQUEST_RESPONSE).build());
                    }

                    @Test
                    @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithErrorCode() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertEquals(INVALID_REQUEST_ERROR.getErrorCode(), modelAndView.getModel().get("error_code"));
                    }

                    @Test
                    @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithErrorDescription() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertEquals(INVALID_REQUEST_ERROR.getDescription(), modelAndView.getModel().get("error_description"));
                    }

                    @Test
                    @DisplayName("STATE 를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithState() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertEquals(STATE, modelAndView.getModel().get("state"));
                    }
                }

                @Nested
                @DisplayName("요청 정보에 state 가 존재하지 않을시")
                class WhenRequestingExcludingState {
                    private Exception exception;
                    private ServletWebRequest servletWebRequest;
                    private AuthorizationEndpoint endpoint;

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mockClientDetails().configDefault().build();
                        OAuth2ClientDetailsService clientDetailsService = mockClientDetailsService().registerClient(clientDetails).build();
                        HttpServletRequest servletRequest = mockHttpServletRequest().configDefault().configNullState().build();

                        this.exception = new Exception("TEST");
                        this.servletWebRequest = new ServletWebRequest(servletRequest, mock(HttpServletResponse.class));

                        this.endpoint = new AuthorizationEndpoint(clientDetailsService, mockScopeDetailsService().build(), mockCodeGenerator().build());
                        this.endpoint.setRedirectResolver(mockRedirectResolver().configResolve(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI).build());
                        this.endpoint.setSessionAttributeStore(mockSessionAttributeStore().configRetrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, null).build());
                        this.endpoint.setExceptionTranslator(mockExceptionTranslator().configTranslate(exception, INVALID_REQUEST_RESPONSE).build());
                    }

                    @Test
                    @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithErrorCode() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertEquals(INVALID_REQUEST_ERROR.getErrorCode(), modelAndView.getModel().get("error_code"));
                    }

                    @Test
                    @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithErrorDescription() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertEquals(INVALID_REQUEST_ERROR.getDescription(), modelAndView.getModel().get("error_description"));
                    }

                    @Test
                    @DisplayName("STATE 를 매개변수에서 제외하고 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithState() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertNull(modelAndView.getModel().get("state"));
                    }
                }
            }
        }

        @Nested
        @DisplayName("세션에 인가 요청 정보가 남아 있을시")
        class WhenAuthorizationRequestRemainedInSession {

            @Nested
            @DisplayName("클라이언트 정보 검색중 예외가 발생할시")
            class WhenThrowsExceptionDuringClientLookup {
                private Exception exception;
                private ServletWebRequest servletWebRequest;
                private AuthorizationEndpoint endpoint;

                @BeforeEach
                void setup() {
                    OAuth2ClientDetailsService clientDetailsService = mockClientDetailsService().emptyClient().build();
                    AuthorizationRequest storedRequest = mockAuthorizationRequest().configDefault().build();

                    this.exception = new Exception("TEST");
                    this.servletWebRequest = new ServletWebRequest(mock(HttpServletRequest.class), mock(HttpServletResponse.class));

                    this.endpoint = new AuthorizationEndpoint(clientDetailsService, mockScopeDetailsService().build(), mockCodeGenerator().build());
                    this.endpoint.setSessionAttributeStore(mockSessionAttributeStore().configRetrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, storedRequest).build());
                    this.endpoint.setExceptionTranslator(mockExceptionTranslator().configTranslate(exception, INVALID_REQUEST_RESPONSE).build());
                }

                @Test
                @DisplayName("에러 페이지로 포워딩 해야 한다.")
                void shouldForwardingErrorPage() {
                    ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                    assertEquals("/oauth/error", modelAndView.getViewName());
                }

                @Test
                @DisplayName("ModelAndView 에 OAuth2 에러 정보를 저장해야 한다.")
                void shouldSaveOAuth2ErrorCodeToModelAndView() {
                    ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                    assertEquals(INVALID_REQUEST_ERROR, modelAndView.getModel().get("error"));
                }
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 주소가 유효하지 않을시")
            class WhenRequestingRedirectUriNotAllowed {
                private Exception exception;
                private ServletWebRequest servletWebRequest;
                private AuthorizationEndpoint endpoint;

                @BeforeEach
                void setup() {
                    OAuth2ClientDetails clientDetails = mockClientDetails().configDefault().build();
                    OAuth2ClientDetailsService clientDetailsService = mockClientDetailsService().registerClient(clientDetails).build();
                    AuthorizationRequest storedRequest = mockAuthorizationRequest().configDefault().build();

                    this.exception = new Exception("TEST");
                    this.servletWebRequest = new ServletWebRequest(mock(HttpServletRequest.class), mock(HttpServletResponse.class));

                    this.endpoint = new AuthorizationEndpoint(clientDetailsService, mockScopeDetailsService().build(), mockCodeGenerator().build());
                    this.endpoint.setSessionAttributeStore(mockSessionAttributeStore().configRetrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, storedRequest).build());
                    this.endpoint.setRedirectResolver(mockRedirectResolver().configMismatched(clientDetails, RAW_RESOLVED_REDIRECT_URI).build());
                    this.endpoint.setExceptionTranslator(mockExceptionTranslator().configTranslate(exception, INVALID_REQUEST_RESPONSE).build());
                }

                @Test
                @DisplayName("에러 페이지로 포워딩 해야 한다.")
                void shouldForwardingErrorPage() {
                    ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                    assertEquals("/oauth/error", modelAndView.getViewName());
                }

                @Test
                @DisplayName("ModelAndView 에 OAuth2 에러 정보를 저장해야 한다.")
                void shouldSaveOAuth2ErrorCodeToModelAndView() {
                    ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                    assertEquals(INVALID_REQUEST_ERROR, modelAndView.getModel().get("error"));
                }
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 주소가 유효할시")
            class WhenRequestingRedirectUriAllowed {

                @Nested
                @DisplayName("요청 정보에 state 가 존재할시")
                class WhenRequestingIncludeState {
                    private Exception exception;
                    private ServletWebRequest servletWebRequest;
                    private AuthorizationEndpoint endpoint;

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mockClientDetails().configDefault().build();
                        OAuth2ClientDetailsService clientDetailsService = mockClientDetailsService().registerClient(clientDetails).build();
                        AuthorizationRequest storedRequest = mockAuthorizationRequest().configDefault().configState().build();

                        this.exception = new Exception("TEST");
                        this.servletWebRequest = new ServletWebRequest(mock(HttpServletRequest.class), mock(HttpServletResponse.class));

                        this.endpoint = new AuthorizationEndpoint(clientDetailsService, mockScopeDetailsService().build(), mockCodeGenerator().build());
                        this.endpoint.setSessionAttributeStore(mockSessionAttributeStore().configRetrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, storedRequest).build());
                        this.endpoint.setRedirectResolver(mockRedirectResolver().configResolve(clientDetails, RAW_RESOLVED_REDIRECT_URI, RESOLVED_REDIRECT_URI).build());
                        this.endpoint.setExceptionTranslator(mockExceptionTranslator().configTranslate(exception, INVALID_REQUEST_RESPONSE).build());
                    }

                    @Test
                    @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithErrorCode() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertEquals(INVALID_REQUEST_ERROR.getErrorCode(), modelAndView.getModel().get("error_code"));
                    }

                    @Test
                    @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithErrorDescription() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertEquals(INVALID_REQUEST_ERROR.getDescription(), modelAndView.getModel().get("error_description"));
                    }

                    @Test
                    @DisplayName("STATE 를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithState() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertEquals(STATE, modelAndView.getModel().get("state"));
                    }
                }

                @Nested
                @DisplayName("요청 정보에 state 가 존재하지 않을시")
                class WhenRequestingExcludingState {
                    private Exception exception;
                    private ServletWebRequest servletWebRequest;
                    private AuthorizationEndpoint endpoint;

                    @BeforeEach
                    void setup() {
                        OAuth2ClientDetails clientDetails = mockClientDetails().configDefault().build();
                        OAuth2ClientDetailsService clientDetailsService = mockClientDetailsService().registerClient(clientDetails).build();
                        AuthorizationRequest storedRequest = mockAuthorizationRequest().configDefault().configNullState().build();

                        this.exception = new Exception("TEST");
                        this.servletWebRequest = new ServletWebRequest(mock(HttpServletRequest.class), mock(HttpServletResponse.class));

                        this.endpoint = new AuthorizationEndpoint(clientDetailsService, mockScopeDetailsService().build(), mockCodeGenerator().build());
                        this.endpoint.setSessionAttributeStore(mockSessionAttributeStore().configRetrieveAttribute(servletWebRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, storedRequest).build());
                        this.endpoint.setRedirectResolver(mockRedirectResolver().configResolve(clientDetails, RAW_RESOLVED_REDIRECT_URI, RESOLVED_REDIRECT_URI).build());
                        this.endpoint.setExceptionTranslator(mockExceptionTranslator().configTranslate(exception, INVALID_REQUEST_RESPONSE).build());
                    }

                    @Test
                    @DisplayName("에러 코드를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithErrorCode() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertEquals(INVALID_REQUEST_ERROR.getErrorCode(), modelAndView.getModel().get("error_code"));
                    }

                    @Test
                    @DisplayName("에러 메시지를 매개변수에 추가하여 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithErrorDescription() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertEquals(INVALID_REQUEST_ERROR.getDescription(), modelAndView.getModel().get("error_description"));
                    }

                    @Test
                    @DisplayName("STATE 를 매개변수에서 제외하고 리다이렉트 주소로 리다이렉트 해야 한다.")
                    void shouldRedirectWithState() {
                        ModelAndView modelAndView = endpoint.handleOtherException(exception, servletWebRequest);

                        assertNotNull(modelAndView.getView());
                        assertEquals(RedirectView.class.getName(), modelAndView.getView().getClass().getName());
                        assertNull(modelAndView.getModel().get("state"));
                    }
                }
            }
        }
    }

    private static abstract class AuthorizationRequestEndpointAssertSetup {
        protected Map<String, String> parameter;
        protected Map<String, Object> model;
        protected Principal principal;
        protected AuthorizationEndpoint endpoint;

        @BeforeEach
        void setup() {
            OAuth2ClientDetails clientDetails = mockClientDetails().configDefault().build();
            OAuth2ClientDetailsService clientDetailsService = mockClientDetailsService().registerClient(clientDetails).build();
            OAuth2RequestValidator requestValidator = mockRequestValidator()
                    .configAllowedScopes(clientDetails, SCOPE)
                    .configAllowedScopes(clientDetails, null)
                    .configAllowedScopes(clientDetails, Collections.emptySet()).build();
            RedirectResolver redirectResolver = mockRedirectResolver().configResolve(clientDetails, RAW_REDIRECT_URI, RESOLVED_REDIRECT_URI).build();

            AuthorizationEndpointTestHelper.MockScopeDetailsService scopeDetailsService = mockScopeDetailsService().registerScopes(SCOPE, SCOPE_DETAILS).registerScopes(CLIENT_SCOPE, CLIENT_SCOPE_DETAILS);
            AuthorizationEndpointTestHelper.MockAuthorizationRequestMap requestMap = mockAuthorizationRequestMap().configDefault();
            configRequestMap(requestMap);
            configScopeDetailsService(scopeDetailsService);

            this.parameter = requestMap.build();
            this.model = new HashMap<>();
            this.principal = mockAuthorizedAuthentication();
            this.endpoint = new AuthorizationEndpoint(clientDetailsService, scopeDetailsService.build(), mockCodeGenerator().build());
            this.endpoint.setRequestValidator(requestValidator);
            this.endpoint.setRedirectResolver(redirectResolver);
            this.endpoint.setApprovalPage(FORWARD_PAGE);
        }

        protected void configRequestMap(AuthorizationEndpointTestHelper.MockAuthorizationRequestMap requestMap) {}

        protected void configScopeDetailsService(AuthorizationEndpointTestHelper.MockScopeDetailsService service) {}

        @Test
        @DisplayName("요청 받은 정보를 세션에 저장해야 한다.")
        void shouldSaveRequestingClientIdToSession() {
            endpoint.authorize(parameter, model, principal);

            AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
            assertEquals(RAW_CLIENT_ID, storedRequest.getClientId());
            assertEquals(RAW_USERNAME, storedRequest.getUsername());
            assertEquals(STATE, storedRequest.getState());
            assertEquals(RESOLVED_REDIRECT_URI, storedRequest.getRedirectUri());
        }

        @Test
        @DisplayName("요청 받은 매개변수들을 세션에 저장해야 한다.")
        void shouldSaveRequestingParameterToSession() {
            endpoint.authorize(parameter, model, principal);

            assertEquals(parameter, model.get(AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE));
        }

        @Test
        @DisplayName("설정된 Approval 페이지로 포워딩 되어야한다.")
        void shouldForwardingConfigApprovalPage() {
            ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);

            assertEquals("forward:" + FORWARD_PAGE, modelAndView.getViewName());
        }

        @Test
        @DisplayName("클라이언트명을 ModelAndView 에 저장해야 한다.")
        void shouldSaveClientNameToModeAndView() {
            ModelAndView modelAndView = endpoint.authorize(parameter, model, principal);

            assertEquals(CLIENT_NAME, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_CLIENT_NAME));
        }
    }

    private static abstract class AuthorizationSuccessAssertSetup {
        protected Map<String, String> approvalParameter;
        protected Map<String, String> originalAuthorizationRequestMap;
        protected Map<String, Object> model;
        protected SessionStatus sessionStatus;
        protected Authentication authentication;
        protected AuthorizationRequest originalAuthorizationRequest;
        protected OAuth2AuthorizationCodeGenerator codeGenerator;
        protected AuthorizationEndpoint endpoint;

        @BeforeEach
        void setup() {
            AuthorizationEndpointTestHelper.MockAuthorizationRequest originalRequest = mockAuthorizationRequest().configDefault();

            configOriginalAuthorizationRequest(originalRequest);

            this.approvalParameter = new HashMap<>();
            this.originalAuthorizationRequestMap = new HashMap<>();
            this.model = new HashMap<>();
            this.sessionStatus = mock(SessionStatus.class);
            this.authentication = mockAuthorizedAuthentication();
            this.originalAuthorizationRequest = originalRequest.build();
            this.codeGenerator = mockCodeGenerator().configGenerated().build();
            this.endpoint = new AuthorizationEndpoint(mockClientDetailsService().build(), mockScopeDetailsService().build(), codeGenerator);

            configOriginalAuthorizationRequestMap(originalAuthorizationRequestMap);

            this.model.put(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE, originalAuthorizationRequest);
            this.model.put(AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE, originalAuthorizationRequestMap);
            this.endpoint.setApprovalResolver(mockScopeApprovalResolver().configResolve(originalAuthorizationRequest, approvalParameter, RAW_RESOLVED_SCOPES).build());
        }

        protected void configOriginalAuthorizationRequest(AuthorizationEndpointTestHelper.MockAuthorizationRequest request) {}

        protected void configOriginalAuthorizationRequestMap(Map<String, String> originalRequestMap) {}

        @Test
        @DisplayName("원본 인가 요청에는 어떤 설정도 하지 않아야 한다.")
        void shouldNotConfigOriginalAuthorizationRequest() {
            endpoint.approval(approvalParameter, model, sessionStatus, authentication);

            verify(originalAuthorizationRequest, never()).setRequestScopes(any());
            verify(originalAuthorizationRequest, never()).setRedirectUri(any());
        }

        @Test
        @DisplayName("요청 받은 클라이언트 아이디로 새 코드를 부여해야 한다.")
        void shouldGrantNewCodeUsingRequestingClientId() {
            ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

            endpoint.approval(approvalParameter, model, sessionStatus, authentication);
            verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
            assertEquals(RAW_CLIENT_ID, requestCaptor.getValue().getClientId());
        }

        @Test
        @DisplayName("Resolver 에서 반환된 스코프로 새 코드를 부여해야 한다.")
        void shouldGrantNewCodeUsingResolvedScope() {
            ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

            endpoint.approval(approvalParameter, model, sessionStatus, authentication);
            verify(codeGenerator, times(1)).generateNewAuthorizationCode(requestCaptor.capture());
            assertEquals(RAW_RESOLVED_SCOPES, requestCaptor.getValue().getRequestScopes());
        }

        @Test
        @DisplayName("요청한 리다이렉트 주소로 리다이렉트 하는 View 를 설정해야 한다.")
        void shouldConfigRedirectToRequestingRedirectUriView() {
            ModelAndView modelAndView = endpoint.approval(approvalParameter, model, sessionStatus, authentication);

            assertTrue(modelAndView.getView() instanceof RedirectView);
            assertEquals(RESOLVED_REDIRECT_URI.toString(), ((RedirectView) modelAndView.getView()).getUrl());
        }

        @Test
        @DisplayName("ModelAndView 에 새로 생성한 인가 코드를 저장해야 한다.")
        void shouldSaveStateTokenToModelAndView() {
            ModelAndView modelAndView = endpoint.approval(approvalParameter, model, sessionStatus, authentication);

            assertEquals(RAW_AUTHORIZATION_CODE, modelAndView.getModel().get(OAuth2Utils.AuthorizationResponseKey.CODE));
        }
    }
}
