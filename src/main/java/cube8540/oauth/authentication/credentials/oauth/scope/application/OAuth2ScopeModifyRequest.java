package cube8540.oauth.authentication.credentials.oauth.scope.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({
        "description", "removeAccessibleAuthority", "newAccessibleAuthority"
}))
public class OAuth2ScopeModifyRequest {

    private String description;

    private List<String> removeAccessibleAuthority;

    private List<String> newAccessibleAuthority;

}
