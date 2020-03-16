package cube8540.oauth.authentication.credentials.authority.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;
import java.util.List;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"resourceId", "resource", "method", "authorities"}))
public class SecuredResourceRegisterRequest {

    private String resourceId;

    private String resource;

    private String method;

    private List<String> authorities;

}
