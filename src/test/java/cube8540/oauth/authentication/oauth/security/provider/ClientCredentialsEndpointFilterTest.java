package cube8540.oauth.authentication.oauth.security.provider;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.BASIC_AUTH_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.BASIC_AUTH_CLIENT_SECRET;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.CLIENT_SECRET;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.FILTER_PATH;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeAuthentication;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeAuthenticationManager;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeBasicAuthenticationHttpServletRequest;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeFilterChain;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeGetHttpServletRequest;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeHttpServletResponse;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeParameterHttpServletRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 인증 엔드포인트 필터 테스트")
class ClientCredentialsEndpointFilterTest {

    @Test
    @DisplayName("ONLY_POST 속성이 true로 설정 되어 있을때 요청을 POST 이외로 시도 했을시")
    void whenConfigOnlyPostSetTrueAndRequestMethodOtherThanPost() {
        ClientCredentialsEndpointFilter filter = new ClientCredentialsEndpointFilter(FILTER_PATH);
        HttpServletRequest request = makeGetHttpServletRequest();
        HttpServletResponse response = makeHttpServletResponse();

        filter.setOnlyPost(true);

        assertThrows(HttpRequestMethodNotSupportedException.class, () -> filter.attemptAuthentication(request, response));
    }

    @Test
    @DisplayName("요청 정보에서 아이디를 찾을 수 없을때")
    void whenIdCannotFoundInRequest()  {
        ClientCredentialsEndpointFilter filter = new ClientCredentialsEndpointFilter(FILTER_PATH);
        HttpServletRequest request = makeParameterHttpServletRequest();
        HttpServletResponse response = makeHttpServletResponse();
        Authentication authentication = makeAuthentication();
        AuthenticationManager manager = makeAuthenticationManager(authentication);

        SecurityContextHolder.clearContext();
        filter.setAuthenticationManager(manager);
        when(request.getParameter("client_id")).thenReturn(null);

        assertThrows(BadCredentialsException.class, () -> filter.attemptAuthentication(request, response));
    }

    @Test
    @DisplayName("Basic Authentication 인증")
    void basicAuthentication() throws Exception {
        ClientCredentialsEndpointFilter filter = new ClientCredentialsEndpointFilter(FILTER_PATH);
        HttpServletRequest request = makeBasicAuthenticationHttpServletRequest();
        HttpServletResponse response = makeHttpServletResponse();
        Authentication authentication = makeAuthentication();
        AuthenticationManager manager = makeAuthenticationManager(authentication);
        ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

        SecurityContextHolder.clearContext();
        filter.setAuthenticationManager(manager);

        filter.attemptAuthentication(request, response);
        verify(manager, times(1)).authenticate(authenticationCaptor.capture());
        assertEquals(BASIC_AUTH_CLIENT_ID, authenticationCaptor.getValue().getPrincipal());
        assertEquals(BASIC_AUTH_CLIENT_SECRET, authenticationCaptor.getValue().getCredentials());
    }

    @Test
    @DisplayName("매개 변수를 이용한 인증")
    void authenticationByParameter() throws Exception {
        ClientCredentialsEndpointFilter filter = new ClientCredentialsEndpointFilter(FILTER_PATH);
        HttpServletRequest request = makeParameterHttpServletRequest();
        HttpServletResponse response = makeHttpServletResponse();
        Authentication authentication = makeAuthentication();
        AuthenticationManager manager = makeAuthenticationManager(authentication);
        ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);

        SecurityContextHolder.clearContext();
        filter.setAuthenticationManager(manager);

        filter.attemptAuthentication(request, response);
        verify(manager, times(1)).authenticate(authenticationCaptor.capture());
        assertEquals(RAW_CLIENT_ID, authenticationCaptor.getValue().getPrincipal());
        assertEquals(CLIENT_SECRET, authenticationCaptor.getValue().getCredentials());
    }

    @Test
    @DisplayName("이미 인증이 완료된 요청 일때")
    void whenRequestHasAlreadyAuthenticated() throws Exception {
        ClientCredentialsEndpointFilter filter = new ClientCredentialsEndpointFilter(FILTER_PATH);
        HttpServletRequest request = makeParameterHttpServletRequest();
        HttpServletResponse response = makeHttpServletResponse();
        Authentication authentication = makeAuthentication();

        SecurityContextHolder.getContext().setAuthentication(authentication);

        Authentication result = filter.attemptAuthentication(request, response);
        assertEquals(authentication, result);
    }

    @Test
    @DisplayName("인증 성공")
    void successfulAuthentication() throws Exception {
        HttpServletRequest request = makeParameterHttpServletRequest();
        HttpServletResponse response = makeHttpServletResponse();
        FilterChain filterChain = makeFilterChain();
        Authentication authentication = makeAuthentication();
        ClientCredentialsEndpointFilter filter = new ClientCredentialsEndpointFilter(FILTER_PATH);

        filter.successfulAuthentication(request, response, filterChain, authentication);
        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
    }
}