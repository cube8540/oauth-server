package cube8540.oauth.authentication.credentials.oauth.authorize.endpoint;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AuthorizationCodeGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.UnsupportedResponseTypeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URI;
import java.security.Principal;
import java.util.Arrays;
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
    private OAuth2AuthorizationCodeGenerator codeGenerator;

    private AuthorizationEndpoint endpoint;

    @BeforeEach
    void setup() {
        this.clientDetailsService = mock(OAuth2ClientDetailsService.class);
        this.codeGenerator = mock(OAuth2AuthorizationCodeGenerator.class);

        this.endpoint = new AuthorizationEndpoint(clientDetailsService, codeGenerator);
    }

    @Nested
    @DisplayName("인가")
    class Authorize {

        @Nested
        @DisplayName("인증 정보가 Authentication 타입이 아닐시")
        class WhenPrincipalTypeIsNotAuthentication {

            private Map<String, String> parameter;
            private Map<String, Object> model;
            private SessionStatus sessionStatus;
            private Principal principal;

            @BeforeEach
            @SuppressWarnings("unchecked")
            void setup() {
                this.parameter = mock(Map.class);
                this.model = mock(Map.class);
                this.sessionStatus = mock(SessionStatus.class);
                this.principal = mock(Principal.class);
            }

            @Test
            @DisplayName("InsufficientAuthenticationException이 발생해야 한다.")
            void shouldThrowsInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.authorize(parameter, model, sessionStatus, principal));
            }
        }

        @Nested
        @DisplayName("인증 정보의 인증 여부가 false일시")
        class WhenAuthenticationObjectIsNotAuthenticated {

            private Map<String, String> parameter;
            private Map<String, Object> model;
            private SessionStatus sessionStatus;
            private Authentication principal;

            @BeforeEach
            @SuppressWarnings("unchecked")
            void setup() {
                this.parameter = mock(Map.class);
                this.model = mock(Map.class);
                this.sessionStatus = mock(SessionStatus.class);
                this.principal = mock(Authentication.class);

                when(principal.isAuthenticated()).thenReturn(false);
            }

            @Test
            @DisplayName("InsufficientAuthenticationException이 발생해야 한다.")
            void shouldThrowsInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.authorize(parameter, model, sessionStatus, principal));
            }
        }

        @Nested
        @DisplayName("유저 인증을 완료한 요청일시")
        class WhenAuthenticationCompletedRequesting {

            private Map<String, Object> model;
            private SessionStatus sessionStatus;
            private Authentication principal;

            @BeforeEach
            void setup() {
                this.model = new HashMap<>();
                this.sessionStatus = mock(SessionStatus.class);
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
                    assertThrows(UnsupportedResponseTypeException.class, () -> endpoint.authorize(parameter, model, sessionStatus, principal));
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
                    assertThrows(UnsupportedResponseTypeException.class, () -> endpoint.authorize(parameter, model, sessionStatus, principal));
                }
            }

            @Nested
            @DisplayName("요청 받은 응답 타입이 code일시")
            class WhenRequestingResponseTypeIsCode {

                private Map<String, String> parameter;
                private OAuth2RequestValidator requestValidator;
                private OAuth2ClientDetails clientDetails;

                @BeforeEach
                void setup() {
                    this.parameter = new HashMap<>();
                    RedirectResolver redirectResolver = mock(RedirectResolver.class);
                    this.requestValidator = mock(OAuth2RequestValidator.class);
                    this.clientDetails = mock(OAuth2ClientDetails.class);
                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.STATE, STATE);
                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI, RAW_REDIRECT_URI);
                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID, RAW_CLIENT_ID);
                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.SCOPE, RAW_SCOPE);
                    this.parameter.put(OAuth2Utils.AuthorizationRequestKey.RESPONSE_TYPE, RESPONSE_TYPE);

                    when(clientDetailsService.loadClientDetailsByClientId(RAW_CLIENT_ID)).thenReturn(clientDetails);
                    when(redirectResolver.resolveRedirectURI(RAW_REDIRECT_URI, clientDetails)).thenReturn(RESOLVED_REDIRECT_URI);
                    when(requestValidator.validateScopes(clientDetails, SCOPE)).thenReturn(true);
                    when(codeGenerator.generateNewAuthorizationCode(any(AuthorizationRequest.class))).thenReturn(CODE);
                    when(clientDetails.scope()).thenReturn(CLIENT_SCOPE);
                    when(clientDetails.clientName()).thenReturn(CLIENT_NAME);

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
                        assertThrows(InvalidGrantException.class, () -> endpoint.authorize(parameter, model, sessionStatus, principal));
                    }

                    @AfterEach
                    void after() {
                        when(requestValidator.validateScopes(clientDetails, SCOPE)).thenReturn(true);
                    }
                }

                @Test
                @DisplayName("요청 받은 클라이언트 아이디를 세션에 저장해야 한다.")
                void shouldSaveRequestingClientIdToSession() {
                    endpoint.authorize(parameter, model, sessionStatus, principal);

                    AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                    assertEquals(RAW_CLIENT_ID, storedRequest.clientId());
                }

                @Test
                @DisplayName("요청 받은 유저명을 세션에 저장해야 한다.")
                void shouldSaveRequestingUsernameToSession() {
                    endpoint.authorize(parameter, model, sessionStatus, principal);

                    AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                    assertEquals(RAW_USERNAME, storedRequest.username());
                }

                @Test
                @DisplayName("요청 받은 STATE를 세션에 저장해야 한다.")
                void shouldSaveRequestingStateToSession() {
                    endpoint.authorize(parameter, model, sessionStatus, principal);

                    AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                    assertEquals(STATE, storedRequest.state());
                }

                @Test
                @DisplayName("요청 받은 리다이렉트 주소를 세션에 저장해야 한다.")
                void shouldSaveRequestingRedirectUriToSession() {
                    endpoint.authorize(parameter, model, sessionStatus, principal);

                    AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                    assertEquals(RESOLVED_REDIRECT_URI, storedRequest.redirectURI());
                }

                @Test
                @DisplayName("요청 받은 스코프를 세션에 저장해야 한다.")
                void shouldSaveRequestingScopeToSession() {
                    endpoint.authorize(parameter, model, sessionStatus, principal);

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
                        endpoint.authorize(parameter, model, sessionStatus, principal);

                        AuthorizationRequest storedRequest = (AuthorizationRequest) model.get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE);
                        assertEquals(CLIENT_SCOPE, storedRequest.requestScopes());
                    }

                    @Test
                    @DisplayName("클라이언트에 저장된 스코프를 ModelAndView에 저장해야 한다.")
                    void shouldSaveClientScopeToModelAndView() {
                        ModelAndView modelAndView = endpoint.authorize(parameter, model, sessionStatus, principal);

                        assertEquals(CLIENT_SCOPE, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_SCOPES_NAME));
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
                    ModelAndView modelAndView = endpoint.authorize(parameter, model, sessionStatus, principal);

                    assertEquals(FORWARD_PAGE, modelAndView.getViewName());
                }

                @Test
                @DisplayName("클라이언트명을 ModelAndView에 저장해야 한다.")
                void shouldSaveClientNameToModeAndView() {
                    ModelAndView modelAndView = endpoint.authorize(parameter, model, sessionStatus, principal);

                    assertEquals(CLIENT_NAME, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_CLIENT_NAME));
                }

                @Test
                @DisplayName("요청한 스코프를 ModelAndView에 저장해야 한다.")
                void shouldSaveRequestingScopeToModelAndView() {
                    ModelAndView modelAndView = endpoint.authorize(parameter, model, sessionStatus, principal);

                    assertEquals(SCOPE, modelAndView.getModel().get(AuthorizationEndpoint.AUTHORIZATION_REQUEST_SCOPES_NAME));
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
        private ScopeApprovalResolver resolver;
        private Set<String> originalRequestScope;
        private Set<String> resolvedRequestScope;

        @BeforeEach
        void setup() {
            this.approvalParameter = new HashMap<>();
            this.model = new HashMap<>();
            this.sessionStatus = mock(SessionStatus.class);
            this.authentication = mock(Authentication.class);
            this.originalAuthorizationRequest = mock(AuthorizationRequest.class);
            this.resolver = mock(ScopeApprovalResolver.class);
            this.originalRequestScope = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
            this.resolvedRequestScope = new HashSet<>(Arrays.asList("RESOLVED-SCOPE-1", "RESOLVED-SCOPE-2", "RESOLVED-SCOPE-3"));

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

}