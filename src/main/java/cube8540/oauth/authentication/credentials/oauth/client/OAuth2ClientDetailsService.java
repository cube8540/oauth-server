package cube8540.oauth.authentication.credentials.oauth.client;

public interface OAuth2ClientDetailsService {

    OAuth2ClientDetails loadClientDetailsByClientId(String clientId);

}
