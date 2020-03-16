package cube8540.oauth.authentication.credentials.authority.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"resource", "method", "newAuthorities", "removeAuthorities"}))
public class SecuredResourceModifyRequest {

    private String resource;

    private String method;

    private List<String> newAuthorities;

    private List<String> removeAuthorities;

}
