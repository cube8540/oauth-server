package cube8540.oauth.authentication.credentials.oauth.security;

import lombok.Value;

import java.io.Serializable;

@Value
public class AuthorizationCode implements Serializable {

    private String value;

}
