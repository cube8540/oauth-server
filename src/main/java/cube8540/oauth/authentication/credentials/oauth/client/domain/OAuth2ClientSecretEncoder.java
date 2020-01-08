package cube8540.oauth.authentication.credentials.oauth.client.domain;

import org.springframework.security.crypto.password.PasswordEncoder;

public interface OAuth2ClientSecretEncoder extends PasswordEncoder {

    boolean matches(OAuth2ClientSecret encryptedSecret, OAuth2ClientSecret rawSecret);

}
