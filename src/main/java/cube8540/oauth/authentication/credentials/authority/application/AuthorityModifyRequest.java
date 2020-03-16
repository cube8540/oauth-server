package cube8540.oauth.authentication.credentials.authority.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({
        "description", "basic", "newAccessibleResources", "removeAccessibleResources"
}))
public class AuthorityModifyRequest {

    private String description;

    private boolean basic;

    private List<String> newAccessibleResources;

    private List<String> removeAccessibleResources;

}
