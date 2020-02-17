package cube8540.oauth.authentication.credentials.oauth.client.application;

import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties({"existsSecret", "newSecret"}))
public class OAuth2ChangeSecretRequest {

    private String existsSecret;

    private String newSecret;

}
