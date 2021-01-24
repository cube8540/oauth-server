package cube8540.oauth.authentication.oauth.security.provider;

import cube8540.oauth.authentication.oauth.error.OAuth2ClientRegistrationException;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientCredentialsProviderTestHelper {

    static final String CLIENT_ID_PARAMETER_NAME = "client_id";
    static final String CLIENT_SECRET_PARAMETER_NAME = "client_secret";

    static final String BASIC_AUTH_CLIENT_ID = "AUTH-CLIENT-ID";
    static final String BASIC_AUTH_CLIENT_SECRET = "AUTH-CLIENT-SECRET";

    static final String RAW_CLIENT_ID = "CLIENT_ID";

    static final String CLIENT_SECRET = "CLIENT_SECRET";
    static final String ENCODING_CLIENT_SECRET = "ENCODING_CLIENT_SECRET";

    static final String FILTER_PATH = "/oauth/token";

    static OAuth2ClientDetailsService makeEmptyClientDetailsService() {
        OAuth2ClientDetailsService service = mock(OAuth2ClientDetailsService.class);

        when(service.loadClientDetailsByClientId(any())).thenThrow(new OAuth2ClientRegistrationException(RAW_CLIENT_ID));

        return service;
    }

    static OAuth2ClientDetailsService makeClientDetailsService(String clientId, OAuth2ClientDetails clientDetails) {
        OAuth2ClientDetailsService service = mock(OAuth2ClientDetailsService.class);

        when(service.loadClientDetailsByClientId(clientId)).thenReturn(clientDetails);

        return service;
    }

    static OAuth2ClientDetailsService makeExceptionClientDetailsService() {
        OAuth2ClientDetailsService service = mock(OAuth2ClientDetailsService.class);

        when(service.loadClientDetailsByClientId(any())).thenThrow(new RuntimeException());

        return service;
    }

    static PasswordEncoder makePasswordEncoder(String rawPassword, String encodingPassword) {
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        when(encoder.encode(rawPassword)).thenReturn(encodingPassword);
        when(encoder.matches(rawPassword, encodingPassword)).thenReturn(true);

        return encoder;
    }

    static PasswordEncoder makeMismatchPasswordEncoder(String rawPassword, String encodingPassword) {
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        when(encoder.matches(rawPassword, encodingPassword)).thenReturn(false);

        return encoder;
    }

    static OAuth2ClientDetails makeClientDetails() {
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);

        when(clientDetails.getClientId()).thenReturn(RAW_CLIENT_ID);
        when(clientDetails.getClientSecret()).thenReturn(ENCODING_CLIENT_SECRET);

        return clientDetails;
    }

    static HttpServletRequest makeGetHttpServletRequest() {
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getMethod()).thenReturn(HttpMethod.GET.toString());

        return request;
    }

    static HttpServletRequest makeBasicAuthenticationHttpServletRequest() {
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getMethod()).thenReturn(HttpMethod.POST.toString());
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(httpBasicAuthentication());

        return request;
    }

    static HttpServletRequest makeParameterHttpServletRequest() {
        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(CLIENT_ID_PARAMETER_NAME)).thenReturn(RAW_CLIENT_ID);
        when(request.getParameter(CLIENT_SECRET_PARAMETER_NAME)).thenReturn(CLIENT_SECRET);

        return request;
    }

    static HttpServletResponse makeHttpServletResponse() {
        return mock(HttpServletResponse.class);
    }

    static String httpBasicAuthentication() {
        String basicAuthentication = BASIC_AUTH_CLIENT_ID + ":" + BASIC_AUTH_CLIENT_SECRET;
        return "Basic"+ " " + Base64.getEncoder().encodeToString(basicAuthentication.getBytes());
    }

    static Authentication makeAuthentication() {
        Authentication authentication = mock(Authentication.class);

        when(authentication.isAuthenticated()).thenReturn(true);

        return authentication;
    }

    static AuthenticationManager makeAuthenticationManager(Authentication authentication) {
        AuthenticationManager manager = mock(AuthenticationManager.class);
        when(manager.authenticate(any())).thenReturn(authentication);
        return manager;
    }

    static FilterChain makeFilterChain() {
        return mock(FilterChain.class);
    }
}