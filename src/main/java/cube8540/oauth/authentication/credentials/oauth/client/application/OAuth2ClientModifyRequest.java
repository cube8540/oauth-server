package cube8540.oauth.authentication.credentials.oauth.client.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({
        "clientName", "newRedirectUris", "removeRedirectUri", "newGrantTypes", "removeGrantTypes", "newScopes", "removeScopes"
}))
public class OAuth2ClientModifyRequest {

    private String clientName;

    private List<String> newRedirectUris;

    private List<String> removeRedirectUris;

    private List<String> newGrantTypes;

    private List<String> removeGrantTypes;

    private List<String> newScopes;

    private List<String> removeScopes;

}
