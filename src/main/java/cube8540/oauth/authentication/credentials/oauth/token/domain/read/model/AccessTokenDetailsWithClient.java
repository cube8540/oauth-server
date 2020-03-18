package cube8540.oauth.authentication.credentials.oauth.token.domain.read.model;

import java.time.LocalDateTime;
import java.util.Map;

public interface AccessTokenDetailsWithClient {

    String getTokenValue();

    AccessTokenClient getClient();

    String getUsername();

    LocalDateTime getIssuedAt();

    long getExpiresIn();

    Map<String, String> getAdditionalInformation();

    interface AccessTokenClient {
        String getClientId();

        String getClientName();
    }
}
