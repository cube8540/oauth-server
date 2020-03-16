package cube8540.oauth.authentication.credentials.oauth.security.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("클라이언트 인증 엔드포인트 필터 테스트")
class ClientCredentialsEndpointFilterTest {

    @Nested
    @DisplayName("인증 시도")
    class AttemptAuthentication {

        @Nested
        @DisplayName("Only Post 속성이 true 로 설정되어 있을때 요청을 POST 이외로 시도 했을시")
        class WhenConfigOnlyPostRequestingMethodIsNotPost {
            private ClientCredentialsEndpointFilter filter;

            @BeforeEach
            void setup() {
                this.filter = new ClientCredentialsEndpointFilter(ClientCredentialsProviderTestHelper.FILTER_PATH);
                this.filter.setOnlyPost(true);
            }

            @Test
            @DisplayName("HttpRequestMethodNotSupportedException 이 발생해야 한다.")
            void shouldThrowsHttpRequestMethodNotSupportedException() {
                HttpServletRequest request = ClientCredentialsProviderTestHelper.mockHttpServletRequest().configMethod(HttpMethod.GET).build();
                HttpServletResponse response = ClientCredentialsProviderTestHelper.mockHttpServletResponse();

                assertThrows(HttpRequestMethodNotSupportedException.class, () -> filter.attemptAuthentication(request, response));
            }
        }

        @Nested
        @DisplayName("SecurityContext 에 인증정보가 없을시")
        class WhenSecurityContextNotHasAuthentication {

            @Nested
            @DisplayName("헤더에 Authentication 옵션이 존재할시")
            class WhenHeaderHasAuthenticationOption extends AuthenticationAssertSetup {

                @Override
                protected HttpServletRequest configRequest() {
                    return ClientCredentialsProviderTestHelper.mockHttpServletRequest().configDefaultBasicAuthentication().build();
                }

                @Override
                protected void configSecurityContext() {
                    SecurityContextHolder.clearContext();
                }

                @Test
                @DisplayName("헤더에 있는 클라이언트의 아이디와 비밀번호로 인증을 진행해야 한다.")
                void shouldAuthenticationByClientIdAndSecret() throws Exception {
                    ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

                    filter.attemptAuthentication(httpServletRequest, httpServletResponse);
                    verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
                    Assertions.assertEquals(ClientCredentialsProviderTestHelper.BASIC_AUTH_CLIENT_ID, authenticationCaptor.getValue().getPrincipal());
                    Assertions.assertEquals(ClientCredentialsProviderTestHelper.BASIC_AUTH_CLIENT_SECRET, authenticationCaptor.getValue().getCredentials());
                }
            }

            @Nested
            @DisplayName("헤더에 Authentication 옵션이 존재하지 않을시")
            class WhenHeaderNotHasAuthenticationOption extends AuthenticationAssertSetup {

                @Override
                protected HttpServletRequest configRequest() {
                    return ClientCredentialsProviderTestHelper.mockHttpServletRequest().configDefaultClientId().configDefaultClientSecret().build();
                }

                @Override
                protected void configSecurityContext() {
                    SecurityContextHolder.clearContext();
                }

                @Test
                @DisplayName("매개변수에서 받은 클라이언트의 아이디와 비밀번호로 인증을 진행해야 한다.")
                void shouldAuthenticationByClientIdAndSecret() throws Exception {
                    ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

                    filter.attemptAuthentication(httpServletRequest, httpServletResponse);
                    verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
                    Assertions.assertEquals(ClientCredentialsProviderTestHelper.RAW_CLIENT_ID, authenticationCaptor.getValue().getPrincipal());
                    Assertions.assertEquals(ClientCredentialsProviderTestHelper.CLIENT_SECRET, authenticationCaptor.getValue().getCredentials());
                }
            }

            @Nested
            @DisplayName("요청 매개변수에서 클라이언트 아이디를 찾을 수 없을시")
            class WhenRequestParameterNotFoundClientId {
                private ClientCredentialsEndpointFilter filter;

                @BeforeEach
                void setup() {
                    this.filter = new ClientCredentialsEndpointFilter(ClientCredentialsProviderTestHelper.FILTER_PATH);
                }

                @Test
                @DisplayName("BadCredentialsException 이 발생해야 한다.")
                void shouldThrowsBadCredentialsException() {
                    HttpServletRequest request = ClientCredentialsProviderTestHelper.mockHttpServletRequest().configDefaultClientSecret().build();

                    assertThrows(BadCredentialsException.class, () -> filter.attemptAuthentication(request, ClientCredentialsProviderTestHelper.mockHttpServletResponse()));
                }
            }
        }

        @Nested
        @DisplayName("SecurityContext 에 인증정보가 있을시")
        class WhenSecurityContextHasAuthentication {

            @Nested
            @DisplayName("SecurityContext 에 저장된 인증 정보가 이미 인증이 완료되었을시")
            class WhenAlreadyAuthentication {
                private Authentication authentication;
                private ClientCredentialsEndpointFilter filter;

                @BeforeEach
                void setup() {
                    this.authentication = ClientCredentialsProviderTestHelper.mockAuthentication().configAuthenticated().build();
                    this.filter = new ClientCredentialsEndpointFilter(ClientCredentialsProviderTestHelper.FILTER_PATH);

                    SecurityContextHolder.getContext().setAuthentication(this.authentication);
                }

                @Test
                @DisplayName("이미 인증이 완료된 객체를 반환해야 한다.")
                void shouldReturnsAlreadyAuthenticatedObject() throws Exception {
                    HttpServletRequest request = ClientCredentialsProviderTestHelper.mockHttpServletRequest().configDefaultBasicAuthentication().build();

                    Authentication result = filter.attemptAuthentication(request, ClientCredentialsProviderTestHelper.mockHttpServletResponse());

                    assertEquals(authentication, result);
                }

                @AfterEach
                void after() {
                    SecurityContextHolder.clearContext();
                }
            }

            @Nested
            @DisplayName("SecurityContext 에 저장된 인증 정보가 인증이 완료되지 않은 인증 정보일시")
            class WhenNotAuthentication {

                @Nested
                @DisplayName("헤더에 Authentication 옵션이 존재할시")
                class WhenHeaderHasAuthenticationOption extends AuthenticationAssertSetup {

                    @Override
                    protected HttpServletRequest configRequest() {
                        return ClientCredentialsProviderTestHelper.mockHttpServletRequest().configDefaultBasicAuthentication().build();
                    }

                    @Override
                    protected void configSecurityContext() {
                        SecurityContextHolder.getContext().setAuthentication(ClientCredentialsProviderTestHelper.mockAuthentication().configNotAuthenticated().build());
                    }

                    @Test
                    @DisplayName("헤더에 있는 클라이언트의 아이디와 비밀번호로 인증을 진행해야 한다.")
                    void shouldAuthenticationByClientIdAndSecret() throws Exception {
                        ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

                        filter.attemptAuthentication(httpServletRequest, httpServletResponse);
                        verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
                        Assertions.assertEquals(ClientCredentialsProviderTestHelper.BASIC_AUTH_CLIENT_ID, authenticationCaptor.getValue().getPrincipal());
                        Assertions.assertEquals(ClientCredentialsProviderTestHelper.BASIC_AUTH_CLIENT_SECRET, authenticationCaptor.getValue().getCredentials());
                    }
                }

                @Nested
                @DisplayName("헤더에 Authentication 옵션이 존재하지 않을시")
                class WhenHeaderNotHasAuthenticationOption extends AuthenticationAssertSetup {

                    @Override
                    protected HttpServletRequest configRequest() {
                        return ClientCredentialsProviderTestHelper.mockHttpServletRequest().configDefaultClientId().configDefaultClientSecret().build();
                    }

                    @Override
                    protected void configSecurityContext() {
                        SecurityContextHolder.getContext().setAuthentication(ClientCredentialsProviderTestHelper.mockAuthentication().configNotAuthenticated().build());
                    }

                    @Test
                    @DisplayName("매개변수에서 받은 클라이언트의 아이디와 비밀번호로 인증을 진행해야 한다.")
                    void shouldAuthenticationByClientIdAndSecret() throws Exception {
                        ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

                        filter.attemptAuthentication(httpServletRequest, httpServletResponse);
                        verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
                        Assertions.assertEquals(ClientCredentialsProviderTestHelper.RAW_CLIENT_ID, authenticationCaptor.getValue().getPrincipal());
                        Assertions.assertEquals(ClientCredentialsProviderTestHelper.CLIENT_SECRET, authenticationCaptor.getValue().getCredentials());
                    }
                }

                @Nested
                @DisplayName("요청 매개변수에서 클라이언트 아이디를 찾을 수 없을시")
                class WhenRequestParameterNotFoundClientId {
                    private ClientCredentialsEndpointFilter filter;

                    @BeforeEach
                    void setup() {
                        this.filter = new ClientCredentialsEndpointFilter(ClientCredentialsProviderTestHelper.FILTER_PATH);
                    }

                    @Test
                    @DisplayName("BadCredentialsException 이 발생해야 한다.")
                    void shouldThrowsBadCredentialsException() {
                        HttpServletRequest request = ClientCredentialsProviderTestHelper.mockHttpServletRequest().configDefaultClientSecret().build();

                        assertThrows(BadCredentialsException.class, () -> filter.attemptAuthentication(request, ClientCredentialsProviderTestHelper.mockHttpServletResponse()));
                    }
                }
            }
        }
    }

    @Nested
    @DisplayName("인증 성공시")
    class SuccessfulAuthentication {
        private HttpServletRequest request;
        private HttpServletResponse response;
        private FilterChain chain;
        private Authentication authentication;

        private ClientCredentialsEndpointFilter filter;

        @BeforeEach
        void setup() {
            this.request = ClientCredentialsProviderTestHelper.mockHttpServletRequest().build();
            this.response = ClientCredentialsProviderTestHelper.mockHttpServletResponse();
            this.chain = ClientCredentialsProviderTestHelper.mockFilterChain();
            this.authentication = ClientCredentialsProviderTestHelper.mockAuthentication().build();

            this.filter = new ClientCredentialsEndpointFilter(ClientCredentialsProviderTestHelper.FILTER_PATH);
        }

        @Test
        @DisplayName("SecurityContextHolder 에 인증정보를 저장해야 한다.")
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

    static abstract class AuthenticationAssertSetup {
        protected HttpServletRequest httpServletRequest;
        protected HttpServletResponse httpServletResponse;
        protected AuthenticationManager authenticationManager;
        protected Authentication authentication;

        protected ClientCredentialsEndpointFilter filter;

        @BeforeEach
        void setup() {
            this.httpServletRequest = configRequest();
            this.httpServletResponse = ClientCredentialsProviderTestHelper.mockHttpServletResponse();
            this.authentication = ClientCredentialsProviderTestHelper.mockAuthentication().configAuthenticated().build();
            this.authenticationManager = ClientCredentialsProviderTestHelper.mockAuthenticationManager(this.authentication);
            this.filter = new ClientCredentialsEndpointFilter(ClientCredentialsProviderTestHelper.FILTER_PATH);
            this.filter.setAuthenticationManager(authenticationManager);

            configSecurityContext();
        }

        @Test
        @DisplayName("인증에 사용된 객체의 타입은 ClientCredentialsToken 타입이어야 한다.")
        void shouldAuthenticationObjectIsClientCredentialsToken() throws Exception {
            ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

            filter.attemptAuthentication(httpServletRequest, httpServletResponse);
            verify(authenticationManager, times(1)).authenticate(authenticationCaptor.capture());
            assertEquals(ClientCredentialsToken.class, authenticationCaptor.getValue().getClass());
        }

        @Test
        @DisplayName("인증이 완료된 인증정보를 반환해야 한다.")
        void shouldReturnsAuthenticationObject() throws Exception {
            Authentication result = filter.attemptAuthentication(httpServletRequest, httpServletResponse);

            assertEquals(authentication, result);
        }

        @AfterEach
        void after() {
            SecurityContextHolder.clearContext();
        }

        protected abstract HttpServletRequest configRequest();
        protected abstract void configSecurityContext();
    }
}