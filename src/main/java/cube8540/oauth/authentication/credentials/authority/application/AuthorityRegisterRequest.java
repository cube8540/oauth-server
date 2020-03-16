package cube8540.oauth.authentication.credentials.authority.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"code", "description", "basic", "accessibleResources"}))
public class AuthorityRegisterRequest {

    private String code;

    private String description;

    private boolean basic;

    private List<String> accessibleResources;

}
