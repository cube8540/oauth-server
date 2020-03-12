package cube8540.oauth.authentication.credentials.authority.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"resource", "method"}))
public class SecuredResourceModifyRequest {

    private String resource;

    private String method;

}
