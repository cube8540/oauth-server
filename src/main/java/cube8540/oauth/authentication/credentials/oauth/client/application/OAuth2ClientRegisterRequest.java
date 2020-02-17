package cube8540.oauth.authentication.credentials.oauth.client.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"clientId", "secret", "clientName", "redirectUris", "scopes", "grantTypes"}))
public class OAuth2ClientRegisterRequest {

    private String clientId;
    private String secret;
    private String clientName;
    private List<String> redirectUris;
    private List<String> scopes;
    private List<String> grantTypes;

}
