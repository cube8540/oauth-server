package cube8540.oauth.authentication.credentials.oauth.client.application;

import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.Singular;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@Builder
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({
        "clientName", "newRedirectUris", "removeRedirectUri", "newGrantTypes", "removeGrantTypes", "newScopes", "removeScopes"
}))
public class OAuth2ClientModifyRequest {

    private String clientName;

    @Singular("newRedirectUri")
    private List<String> newRedirectUris;

    @Singular("removeRedirectUri")
    private List<String> removeRedirectUris;

    @Singular("newGrantType")
    private List<String> newGrantTypes;

    @Singular("removeGrantType")
    private List<String> removeGrantTypes;

    @Singular("newScope")
    private List<String> newScopes;

    @Singular("removeScope")
    private List<String> removeScopes;

}
