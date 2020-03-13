package cube8540.oauth.authentication.credentials.oauth.security.provider;

import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ClientRegistrationException;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetailsService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;

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

    static MockPasswordEncoder mockPasswordEncoder() {
        return new MockPasswordEncoder();
    }

    static MockOAuth2ClientDetailsService mockOAuth2ClientDetailsService() {
        return new MockOAuth2ClientDetailsService();
    }

    static MockOAuth2ClientDetails mockOAuth2ClientDetails() {
        return new MockOAuth2ClientDetails();
    }

    static MockHttpServletRequest mockHttpServletRequest() {
        return new MockHttpServletRequest();
    }

    static AuthenticationEntryPoint mockEntryPoint() {
        return mock(AuthenticationEntryPoint.class);
    }

    static HttpServletResponse mockHttpServletResponse() {
        return mock(HttpServletResponse.class);
    }

    static MockAuthentication mockAuthentication() {
        return new MockAuthentication();
    }

    static String httpBasicAuthentication() {
        String basicAuthentication = BASIC_AUTH_CLIENT_ID + ":" + BASIC_AUTH_CLIENT_SECRET;
        return "Basic"+ " " + Base64.getEncoder().encodeToString(basicAuthentication.getBytes());
    }

    static AuthenticationManager mockAuthenticationManager(Authentication authentication) {
        AuthenticationManager manager = mock(AuthenticationManager.class);
        when(manager.authenticate(any())).thenReturn(authentication);
        return manager;
    }

    static FilterChain mockFilterChain() {
        return mock(FilterChain.class);
    }

    static class MockPasswordEncoder {
        private PasswordEncoder encoder;

        private MockPasswordEncoder() {
            this.encoder = mock(PasswordEncoder.class);
        }

        MockPasswordEncoder encode() {
            when(encoder.encode(CLIENT_SECRET)).thenReturn(ENCODING_CLIENT_SECRET);
            return this;
        }

        MockPasswordEncoder matches() {
            when(encoder.matches(CLIENT_SECRET, ENCODING_CLIENT_SECRET)).thenReturn(true);
            return this;
        }

        MockPasswordEncoder mismatches() {
            when(encoder.matches(CLIENT_SECRET, ENCODING_CLIENT_SECRET)).thenReturn(false);
            return this;
        }

        PasswordEncoder build() {
            return encoder;
        }
    }

    static class MockOAuth2ClientDetailsService {
        private OAuth2ClientDetailsService service;

        private MockOAuth2ClientDetailsService() {
            this.service = mock(OAuth2ClientDetailsService.class);
        }

        MockOAuth2ClientDetailsService registerClient(OAuth2ClientDetails clientDetails) {
            when(service.loadClientDetailsByClientId(RAW_CLIENT_ID)).thenReturn(clientDetails);
            return this;
        }

        MockOAuth2ClientDetailsService emptyClient() {
            when(service.loadClientDetailsByClientId(RAW_CLIENT_ID)).thenThrow(new OAuth2ClientRegistrationException(RAW_CLIENT_ID + " is not found"));
            return this;
        }

        MockOAuth2ClientDetailsService configThrows() {
            when(service.loadClientDetailsByClientId(any())).thenThrow(new RuntimeException());
            return this;
        }

        OAuth2ClientDetailsService build() {
            return service;
        }
    }

    static class MockOAuth2ClientDetails {
        private OAuth2ClientDetails clientDetails;

        private MockOAuth2ClientDetails() {
            this.clientDetails = mock(OAuth2ClientDetails.class);
        }

        MockOAuth2ClientDetails configDefault() {
            configDefaultClientId();
            configDefaultSecret();
            return this;
        }

        MockOAuth2ClientDetails configDefaultClientId() {
            when(clientDetails.getClientId()).thenReturn(RAW_CLIENT_ID);
            return this;
        }

        MockOAuth2ClientDetails configDefaultSecret() {
            when(clientDetails.getClientSecret()).thenReturn(ENCODING_CLIENT_SECRET);
            return this;
        }

        OAuth2ClientDetails build() {
            return clientDetails;
        }
    }

    static class MockHttpServletRequest {
        private HttpServletRequest request;

        private MockHttpServletRequest() {
            this.request = mock(HttpServletRequest.class);
        }

        MockHttpServletRequest configMethod(HttpMethod method) {
            when(request.getMethod()).thenReturn(method.toString());
            return this;
        }

        MockHttpServletRequest configDefaultClientId() {
            when(request.getParameter(CLIENT_ID_PARAMETER_NAME)).thenReturn(RAW_CLIENT_ID);
            return this;
        }

        MockHttpServletRequest configDefaultClientSecret() {
            when(request.getParameter(CLIENT_SECRET_PARAMETER_NAME)).thenReturn(CLIENT_SECRET);
            return this;
        }

        MockHttpServletRequest configDefaultBasicAuthentication() {
            when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(httpBasicAuthentication());
            return this;
        }

        HttpServletRequest build() {
            return request;
        }
    }

    static class MockAuthentication {
        private Authentication authentication;

        private MockAuthentication() {
            this.authentication = mock(Authentication.class);
        }

        MockAuthentication configAuthenticated() {
            when(authentication.isAuthenticated()).thenReturn(true);
            return this;
        }

        MockAuthentication configNotAuthenticated() {
            when(authentication.isAuthenticated()).thenReturn(false);
            return this;
        }

        Authentication build() {
            return authentication;
        }
    }
}