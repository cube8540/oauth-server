package cube8540.oauth.authentication.credentials.oauth.token.infra.read.model;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.read.model.AccessTokenDetailsWithClient;
import lombok.Value;

import java.time.LocalDateTime;
import java.util.Map;

@Value
public class DefaultAccessTokenDetailsWithClient implements AccessTokenDetailsWithClient {

    private String tokenValue;
    private AccessTokenClient client;
    private String username;
    private LocalDateTime issuedAt;
    private long expiresIn;
    private Map<String, String> additionalInformation;

    public DefaultAccessTokenDetailsWithClient(OAuth2AuthorizedAccessToken accessToken, OAuth2Client client) {
        this.tokenValue = accessToken.getTokenId().getValue();
        this.client = new DefaultClient(client.getClientId().getValue(), client.getClientName());
        this.username = accessToken.getUsername().getValue();
        this.issuedAt = accessToken.getIssuedAt();
        this.expiresIn = accessToken.expiresIn();
        this.additionalInformation = accessToken.getAdditionalInformation();
    }

    @Value
    public static class DefaultClient implements AccessTokenDetailsWithClient.AccessTokenClient {

        private String clientId;
        private String clientName;

    }

}
