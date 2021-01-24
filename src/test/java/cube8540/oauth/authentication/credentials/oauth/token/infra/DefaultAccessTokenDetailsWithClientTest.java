package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.PrincipalUsername;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 엑세스 토큰, 클라이언트 DTO 테스트")
class DefaultAccessTokenDetailsWithClientTest {

    private static final String RAW_TOKEN_VALUE = "TOKEN-VALUE";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_VALUE);

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);
    private static final String CLIENT_NAME = "CLIENT-NAME";

    private static final String RAW_USERNAME = "username";
    private static final PrincipalUsername USERNAME = new PrincipalUsername(RAW_USERNAME);

    private static final LocalDateTime ISSUED_AT = LocalDateTime.of(2020, 3, 18, 18, 2);

    private static final Map<String, String> ADDITIONAL_INFORMATION = new HashMap<>();

    private OAuth2AuthorizedAccessToken accessToken;
    private OAuth2Client client;

    @BeforeEach
    void setup() {
        this.accessToken = mock(OAuth2AuthorizedAccessToken.class);
        this.client = mock(OAuth2Client.class);

        when(accessToken.getTokenId()).thenReturn(TOKEN_ID);
        when(accessToken.getUsername()).thenReturn(USERNAME);
        when(accessToken.getIssuedAt()).thenReturn(ISSUED_AT);
        when(accessToken.getAdditionalInformation()).thenReturn(ADDITIONAL_INFORMATION);

        when(client.getClientId()).thenReturn(CLIENT_ID);
        when(client.getClientName()).thenReturn(CLIENT_NAME);
    }

    @Test
    @DisplayName("토큰, 클라이언트로 인스턴스화")
    void createByAccessTokenAndClient() {
        DefaultAccessTokenDetailsWithClient token = new DefaultAccessTokenDetailsWithClient(accessToken, client);

        assertEquals(token.getTokenValue(), RAW_TOKEN_VALUE);
        assertEquals(token.getUsername(), RAW_USERNAME);
        assertEquals(token.getIssuedAt(), ISSUED_AT);
        assertEquals(token.getAdditionalInformation(), ADDITIONAL_INFORMATION);
        assertEquals(token.getClient().getClientId(), RAW_CLIENT_ID);
        assertEquals(token.getClient().getClientName(), CLIENT_NAME);
    }
}