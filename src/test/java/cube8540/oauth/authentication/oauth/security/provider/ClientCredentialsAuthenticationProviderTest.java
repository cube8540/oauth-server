package cube8540.oauth.authentication.oauth.security.provider;

import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.CLIENT_SECRET;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.ENCODING_CLIENT_SECRET;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeClientDetailsService;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeEmptyClientDetailsService;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeExceptionClientDetailsService;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makeMismatchPasswordEncoder;
import static cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsProviderTestHelper.makePasswordEncoder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("클라이언트 인증 제공 클래스 테스트")
class ClientCredentialsAuthenticationProviderTest {

    @Test
    @DisplayName("요청한 클라이언트를 찾을 수 없을때 인증 진행")
    void authenticationWhenRequestedClientNotFound() {
        ClientCredentialsToken token = new ClientCredentialsToken(RAW_CLIENT_ID, CLIENT_SECRET);
        OAuth2ClientDetailsService service = makeEmptyClientDetailsService();
        PasswordEncoder encoder = makePasswordEncoder(CLIENT_SECRET, ENCODING_CLIENT_SECRET);
        ClientCredentialsAuthenticationProvider provider = new ClientCredentialsAuthenticationProvider(service, encoder);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
    }

    @Test
    @DisplayName("요청한 클라이언트의 아이디가 null 일때 인증 진행")
    void authenticationWhenRequestClientIdIsNull() {
        ClientCredentialsToken token = new ClientCredentialsToken(null ,CLIENT_SECRET);
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2ClientDetailsService service = makeClientDetailsService(RAW_CLIENT_ID, clientDetails);
        PasswordEncoder encoder = makePasswordEncoder(CLIENT_SECRET, ENCODING_CLIENT_SECRET);
        ClientCredentialsAuthenticationProvider provider = new ClientCredentialsAuthenticationProvider(service, encoder);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
    }

    @Test
    @DisplayName("요청한 클라이언트의 패스워드가 null 일때 인증 진행")
    void authenticationWhenRequestClientSecretIsNull() {
        ClientCredentialsToken token = new ClientCredentialsToken(RAW_CLIENT_ID ,null);
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2ClientDetailsService service = makeClientDetailsService(RAW_CLIENT_ID, clientDetails);
        PasswordEncoder encoder = makePasswordEncoder(CLIENT_SECRET, ENCODING_CLIENT_SECRET);
        ClientCredentialsAuthenticationProvider provider = new ClientCredentialsAuthenticationProvider(service, encoder);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
    }

    @Test
    @DisplayName("클라이언트의 패스워드와 요청 받은 패스워드가 일치 하지 않을때 인증 진행")
    void authenticationWhenClientSecretAndRequestedSecretNotMatched() {
        ClientCredentialsToken token = new ClientCredentialsToken(RAW_CLIENT_ID, CLIENT_SECRET);
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2ClientDetailsService service = makeClientDetailsService(RAW_CLIENT_ID, clientDetails);
        PasswordEncoder encoder = makeMismatchPasswordEncoder(CLIENT_SECRET, ENCODING_CLIENT_SECRET);
        ClientCredentialsAuthenticationProvider provider = new ClientCredentialsAuthenticationProvider(service, encoder);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
    }

    @Test
    @DisplayName("클라이언트 인증 진행")
    void authenticationClient() {
        ClientCredentialsToken token = new ClientCredentialsToken(RAW_CLIENT_ID, CLIENT_SECRET);
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2ClientDetailsService service = makeClientDetailsService(RAW_CLIENT_ID, clientDetails);
        PasswordEncoder encoder = makePasswordEncoder(CLIENT_SECRET, ENCODING_CLIENT_SECRET);
        ClientCredentialsAuthenticationProvider provider = new ClientCredentialsAuthenticationProvider(service, encoder);

        Authentication authentication = provider.authenticate(token);
        assertEquals(clientDetails, authentication.getPrincipal());
        assertEquals(ENCODING_CLIENT_SECRET, authentication.getCredentials());
        assertEquals(Collections.emptyList(), authentication.getAuthorities());
        assertTrue(authentication.isAuthenticated());
    }

    @Test
    @DisplayName("인증 중 예상 하지 못한 예외가 발생했을 때")
    void whenUnexpectedExceptionOccursDuringAuthentication() {
        ClientCredentialsToken token = new ClientCredentialsToken(RAW_CLIENT_ID, CLIENT_SECRET);
        OAuth2ClientDetailsService service = makeExceptionClientDetailsService();
        PasswordEncoder encoder = makePasswordEncoder(CLIENT_SECRET, ENCODING_CLIENT_SECRET);
        ClientCredentialsAuthenticationProvider provider = new ClientCredentialsAuthenticationProvider(service, encoder);

        assertThrows(InternalAuthenticationServiceException.class, () -> provider.authenticate(token));
    }
}