package cube8540.oauth.authentication.credentials.oauth.client.domain;

public interface OAuth2ClientSecretEncoder {

    String encoding(String secret);

    boolean matches(OAuth2ClientSecret encryptedSecret, OAuth2ClientSecret rawSecret);

}
