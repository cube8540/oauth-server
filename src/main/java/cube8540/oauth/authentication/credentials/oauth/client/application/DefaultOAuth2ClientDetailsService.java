package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRegistrationException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;

public class DefaultOAuth2ClientDetailsService implements OAuth2ClientDetailsService {

    private final OAuth2ClientRepository repository;

    public DefaultOAuth2ClientDetailsService(OAuth2ClientRepository repository) {
        this.repository = repository;
    }

    @Override
    public OAuth2ClientDetails loadClientDetailsByClientId(String clientId) throws OAuth2ClientRegistrationException {
        return repository.findByClientId(new OAuth2ClientId(clientId))
                .map(DefaultOAuth2ClientDetails::new)
                .orElseThrow(() -> new OAuth2ClientNotFoundException(clientId + " is not found"));
    }
}
