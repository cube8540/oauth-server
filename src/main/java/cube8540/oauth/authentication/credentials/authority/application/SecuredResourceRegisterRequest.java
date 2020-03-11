package cube8540.oauth.authentication.credentials.authority.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"resourceId", "resource", "method"}))
public class SecuredResourceRegisterRequest {

    private String resourceId;

    private String resource;

    private String method;

}
