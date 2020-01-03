package cube8540.oauth.authentication.credentials.oauth.client.domain;

public interface OAuth2ClientSecret {

    String getSecret();

    boolean isEncrypted();

    OAuth2ClientSecret encrypted(OAuth2ClientSecretEncoder encoder);

}
