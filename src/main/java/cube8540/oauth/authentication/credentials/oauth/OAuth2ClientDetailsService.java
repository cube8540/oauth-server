package cube8540.oauth.authentication.credentials.oauth;

public interface OAuth2ClientDetailsService {

    OAuth2ClientDetails loadClientDetailsByClientId(String clientId);

}
