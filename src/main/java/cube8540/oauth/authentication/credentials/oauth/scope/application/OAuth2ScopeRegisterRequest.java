package cube8540.oauth.authentication.credentials.oauth.scope.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"scopeId", "description", "accessibleAuthority"}))
public class OAuth2ScopeRegisterRequest {

    private String scopeId;

    private String description;

    private List<String> accessibleAuthority;

}
