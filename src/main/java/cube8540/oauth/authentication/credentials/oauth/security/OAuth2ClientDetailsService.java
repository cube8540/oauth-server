package cube8540.oauth.authentication.credentials.oauth.security;

public interface OAuth2ClientDetailsService {

    OAuth2ClientDetails loadClientDetailsByClientId(String clientId);

}
