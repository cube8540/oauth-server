package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRegistrationException;

public interface OAuth2ClientDetailsService {

    OAuth2ClientDetails loadClientDetailsByClientId(String clientId) throws OAuth2ClientRegistrationException;

}
