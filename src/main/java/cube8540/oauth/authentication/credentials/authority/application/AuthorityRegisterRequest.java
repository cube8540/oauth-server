package cube8540.oauth.authentication.credentials.authority.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"code", "description", "basic"}))
public class AuthorityRegisterRequest {

    private String code;

    private String description;

    private boolean basic;

}
