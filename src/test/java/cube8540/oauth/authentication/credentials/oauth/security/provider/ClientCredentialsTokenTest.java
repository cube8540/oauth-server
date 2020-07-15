package cube8540.oauth.authentication.credentials.oauth.security.provider;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 인증 토큰 테스트")
class   ClientCredentialsTokenTest {

    private static final String CLIENT_ID = "CLIENT_ID";
    private static final String CLIENT_SECRET = "CLIENT_SECRET";

    private static final Collection<? extends GrantedAuthority> AUTHORITIES = Collections.emptyList();

    @Test
    @DisplayName("토큰 초기화")
    void initializeToken() {
        ClientCredentialsToken token = new ClientCredentialsToken(CLIENT_ID, CLIENT_SECRET);

        assertEquals(CLIENT_ID, token.getPrincipal());
        assertEquals(CLIENT_SECRET, token.getCredentials());
        assertEquals(Collections.emptyList(), token.getAuthorities());
        assertFalse(token.isAuthenticated());
    }

    @Test
    @DisplayName("권한 정보와 함께 토큰 초기화")
    void initializeTokenWithAuthorities() {
        ClientCredentialsToken token = new ClientCredentialsToken(CLIENT_ID, CLIENT_SECRET, AUTHORITIES);

        assertEquals(CLIENT_ID, token.getPrincipal());
        assertEquals(CLIENT_SECRET, token.getCredentials());
        assertEquals(AUTHORITIES, token.getAuthorities());
        assertTrue(token.isAuthenticated());
    }

    @Test
    @DisplayName("토큰의 권한을 설정")
    void setAuthorities() {
        ClientCredentialsToken token = new ClientCredentialsToken(CLIENT_ID, CLIENT_SECRET);

        assertThrows(IllegalArgumentException.class, () -> token.setAuthenticated(true));
        assertFalse(token.isAuthenticated());
    }

    @Test
    @DisplayName("민감한 정보 삭제")
    void eraseSensitiveData() {
        CredentialsContainer principal = mock(CredentialsContainer.class);
        CredentialsContainer credentials = mock(CredentialsContainer.class);
        CredentialsContainer details = mock(CredentialsContainer.class);
        ClientCredentialsToken token = new ClientCredentialsToken(principal, credentials, AUTHORITIES);

        token.setDetails(details);

        token.eraseCredentials();
        assertNull(token.getCredentials());
        verify(principal, times(1)).eraseCredentials();
        verify(credentials, times(1)).eraseCredentials();
        verify(details, times(1)).eraseCredentials();
    }

    @Test
    @DisplayName("인증 정보가 String 타입 일때")
    void whenPrincipalNameTypeString() {
        ClientCredentialsToken token = new ClientCredentialsToken(CLIENT_ID, CLIENT_SECRET);

        assertEquals(CLIENT_ID, token.getName());
    }

    @Test
    @DisplayName("인증 정보가 ClientDetails 타입 일떄")
    void whenPrincipalNameTypeClientDetails() {
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
        ClientCredentialsToken token = new ClientCredentialsToken(clientDetails, CLIENT_SECRET);

        when(clientDetails.getClientId()).thenReturn(CLIENT_ID);

        assertEquals(CLIENT_ID, token.getName());
    }
}