package cube8540.oauth.authentication.credentials.oauth.security;

import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;

public interface OAuth2ClientDetailsService {

    OAuth2ClientDetails loadClientDetailsByClientId(String clientId);

}
