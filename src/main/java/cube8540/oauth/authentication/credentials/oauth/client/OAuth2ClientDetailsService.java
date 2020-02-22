package cube8540.oauth.authentication.credentials.oauth.client;

import cube8540.oauth.authentication.credentials.oauth.client.error.ClientNotFoundException;

public interface OAuth2ClientDetailsService {

    OAuth2ClientDetails loadClientDetailsByClientId(String clientId) throws ClientNotFoundException;

}
