package cube8540.oauth.authentication.credentials.oauth.client.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 인증 엔드포인트 필터 테스트")
class ClientCredentialsEndpointFilterTest {

    private static final String CLIENT_ID = "CLIENT_ID";
    private static final String CLIENT_SECRET = "CLIENT_SECRET";
    private static final String PATH = "/oauth/token";

    private AuthenticationEntryPoint entryPoint;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private Authentication authentication;
    private FilterChain chain;

    private ClientCredentialsEndpointFilter filter;

    @BeforeEach
    void setup() {
        this.entryPoint = mock(AuthenticationEntryPoint.class);
        this.request = mock(HttpServletRequest.class);
        this.response = mock(HttpServletResponse.class);
        this.authentication = mock(Authentication.class);
        this.chain = mock(FilterChain.class);
        this.filter = new ClientCredentialsEndpointFilter(PATH);
        this.filter.setEntryPoint(entryPoint);
    }

    @Nested
    @DisplayName("인증 시도")
    class AttemptAuthentication {

        private AuthenticationManager authenticationManager;

        @BeforeEach
        void setup() {
            this.authenticationManager = mock(AuthenticationManager.class);

            when(authenticationManager.authenticate(any())).thenReturn(authentication);
            filter.setAuthenticationManager(authenticationManager);
        }

        @Nested
        @DisplayName("Only Post 속성이 true로 설정되었을시")
        class WhenNotSupportedMethodType {

            @BeforeEach
            void setup() {
                filter.setOnlyPost(true);
            }

            @Nested
            @DisplayName("요청을 POST 이외로 시도했을시")
            class WhenMethodTypeNotPost {

                @Test
                @DisplayName("HttpRequestMethodNotSupportedException이 발생해야 한다.")
                void shouldThrowsHttpRequestMethodNotSupportedException() {
                    Arrays.asList(HttpMethod.values()).forEach(method -> {
                        if (!method.name().equalsIgnoreCase("POST")) {
                            when(request.getMethod()).thenReturn(method.name());
                            assertThrows(HttpRequestMethodNotSupportedException.class, () -> filter.attemptAuthentication(request, response));
                        }
                    });
                }
            }

            @Nested
            @DisplayName("요청을 POST로 시도했을시")
            class WhenMethodTypePost {

                @Test
                @DisplayName("HttpRequestMethodNotSupportedException이 발생하지 않아야 한다.")
                void shouldNotThrowsHttpRequestMethodNotSupportedException() {
                    when(request.getMethod()).thenReturn(HttpMethod.POST.name());
                    try {
                        filter.attemptAuthentication(request, response);
                    } catch (Exception e) {
                        assertNotEquals(HttpRequestMethodNotSupportedException.class, e.getClass());
                    }
                }
            }

            @AfterEach
            void after() {
                filter.setOnlyPost(false);
            }
        }

        @Nested
        @DisplayName("SecurityContext에 인증정보가 없을시")
        class WhenSecurityContextNotHasAuthentication {

            @BeforeEach
            void setup() {
                when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
                when(request.getParameter("client_secret")).thenReturn(CLIENT_SECRET);
            }

            @Nested
            @DisplayName("헤더에 Authentication 옵션이 존재할시")
            class WhenHeaderHasAuthenticationOption {

                private final String headerUsername = "HEADER_USERNAME";
                private final String headerPassword = "HEADER_PASSWORD";
                private String headerOption;

                @BeforeEach
                void setup() {
                    String basicAuthentication = headerUsername + ":" + headerPassword;
                    this.headerOption = "Basic" + " " +
                            Base64.getEncoder().encodeToString(basicAuthentication.getBytes());

                    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(headerOption);
                    when(request.getParameter(any())).thenReturn(null);
                }

                @Test
                @DisplayName("헤더에 있는 클라이언트의 아이디와 비밀번호로 인증을 진행해야 한다.")
                void shouldAuthenticationByClientIdAndSecret() throws Exception {
                    ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

                    filter.attemptAuthentication(request, response);
                    verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
                    assertEquals(headerUsername, authenticationCaptor.getValue().getPrincipal());
                    assertEquals(headerPassword, authenticationCaptor.getValue().getCredentials());
                }
            }

            @Test
            @DisplayName("매개변수에서 받은 클라이언트의 아이디와 비밀번호로 인증을 진행해야 한다.")
            void shouldAuthenticationByClientIdAndSecret() throws Exception {
                ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

                filter.attemptAuthentication(request, response);
                verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
                assertEquals(CLIENT_ID, authenticationCaptor.getValue().getPrincipal());
                assertEquals(CLIENT_SECRET, authenticationCaptor.getValue().getCredentials());
            }

            @Test
            @DisplayName("인증에 사용된 객체의 타입은 ClientCredentialsToken 타입이어야 한다.")
            void shouldAuthenticationObjectIsClientCredentialsToken() throws Exception {
                ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

                filter.attemptAuthentication(request, response);
                verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
                assertEquals(ClientCredentialsToken.class, authenticationCaptor.getValue().getClass());
            }

            @Test
            @DisplayName("인증이 완료된 인증정보를 반환해야 한다.")
            void shouldReturnsAuthenticationObject() throws Exception {
                Authentication result = filter.attemptAuthentication(request, response);

                assertEquals(authentication, result);
            }

            @Nested
            @DisplayName("요청 매개변수에서 클라이언트 아이디를 찾을 수 없을시")
            class WhenRequestParameterNotFoundClientId {

                @BeforeEach
                void setup() {
                    when(request.getMethod()).thenReturn(HttpMethod.POST.name());
                    when(request.getParameter(any())).thenReturn(null);
                }

                @Test
                @DisplayName("BadCredentialsException이 발생해야 한다.")
                void shouldThrowsBadCredentialsException() {
                    assertThrows(BadCredentialsException.class, () -> filter.attemptAuthentication(request, response));
                }
            }
        }

        @Nested
        @DisplayName("SecurityContext에 인증정보가 있을시")
        class WhenSecurityContextHasAuthentication {

            @BeforeEach
            void setup() {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            @Nested
            @DisplayName("SecurityContext에 저장된 인증 정보가 이미 인증이 완료되었을시")
            class WhenAlreadyAuthentication {

                @BeforeEach
                void setup() {
                    when(authentication.isAuthenticated()).thenReturn(true);
                }

                @Test
                @DisplayName("이미 인증이 완료된 객체를 반환해야 한다.")
                void shouldReturnsAlreadyAuthenticatedObject() throws Exception {
                    Authentication result = filter.attemptAuthentication(request, response);

                    assertEquals(authentication, result);
                }
            }

            @Nested
            @DisplayName("SecurityContext에 저장된 인증 정보가 인증이 완료되지 않은 인증 정보일시")
            class WhenNotAuthentication {

                @BeforeEach
                void setup() {
                    when(authentication.isAuthenticated()).thenReturn(false);
                    when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
                    when(request.getParameter("client_secret")).thenReturn(CLIENT_SECRET);
                }

                @Nested
                @DisplayName("헤더에 Authentication 옵션이 존재할시")
                class WhenHeaderHasAuthenticationOption {

                    private final String headerUsername = "HEADER_USERNAME";
                    private final String headerPassword = "HEADER_PASSWORD";

                    @BeforeEach
                    void setup() {
                        String basicAuthentication = headerUsername + ":" + headerPassword;
                        String headerOption = "Basic" + " " +
                                Base64.getEncoder().encodeToString(basicAuthentication.getBytes());

                        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(headerOption);
                        when(request.getParameter(any())).thenReturn(null);
                    }

                    @Test
                    @DisplayName("헤더에 있는 클라이언트의 아이디와 비밀번호로 인증을 진행해야 한다.")
                    void shouldAuthenticationByClientIdAndSecret() throws Exception {
                        ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

                        filter.attemptAuthentication(request, response);
                        verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
                        assertEquals(headerUsername, authenticationCaptor.getValue().getPrincipal());
                        assertEquals(headerPassword, authenticationCaptor.getValue().getCredentials());
                    }
                }

                @Test
                @DisplayName("매개변수에서 받은 클라이언트의 아이디와 비밀번호로 인증을 진행해야 한다.")
                void shouldAuthenticationByClientIdAndSecret() throws Exception {
                    ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

                    filter.attemptAuthentication(request, response);
                    verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
                    assertEquals(CLIENT_ID, authenticationCaptor.getValue().getPrincipal());
                    assertEquals(CLIENT_SECRET, authenticationCaptor.getValue().getCredentials());
                }

                @Test
                @DisplayName("인증에 사용된 객체의 타입은 ClientCredentialsToken 타입이어야 한다.")
                void shouldAuthenticationObjectIsClientCredentialsToken() throws Exception {
                    ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

                    filter.attemptAuthentication(request, response);
                    verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
                    assertEquals(ClientCredentialsToken.class, authenticationCaptor.getValue().getClass());
                }

                @Test
                @DisplayName("인증이 완료된 인증정보를 반환해야 한다.")
                void shouldReturnsAuthenticationObject() throws Exception {
                    Authentication result = filter.attemptAuthentication(request, response);

                    assertEquals(authentication, result);
                }

                @Nested
                @DisplayName("요청 매개변수에서 클라이언트 아이디를 찾을 수 없을시")
                class WhenRequestParameterNotFoundClientId {

                    @BeforeEach
                    void setup() {
                        when(request.getMethod()).thenReturn(HttpMethod.POST.name());
                        when(request.getParameter(any())).thenReturn(null);
                    }

                    @Test
                    @DisplayName("BadCredentialsException이 발생해야 한다.")
                    void shouldThrowsBadCredentialsException() {
                        assertThrows(BadCredentialsException.class, () -> filter.attemptAuthentication(request, response));
                    }
                }
            }

            @AfterEach
            void after() {
                SecurityContextHolder.clearContext();
            }
        }
    }

    @Nested
    @DisplayName("인증 성공시")
    class SuccessfulAuthentication {

        @Test
        @DisplayName("SecurityContextHolder에 인증정보를 저장해야 한다.")
        void shouldSaveAuthentication() throws Exception {
            filter.successfulAuthentication(request, response, chain, authentication);

            assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
        }

        @Test
        @DisplayName("다음 필터로 채인되어야 한다.")
        void shouldChainNextFilter() throws Exception {
            filter.successfulAuthentication(request, response, chain, authentication);

            verify(chain, times(1)).doFilter(request, response);
        }
    }
}