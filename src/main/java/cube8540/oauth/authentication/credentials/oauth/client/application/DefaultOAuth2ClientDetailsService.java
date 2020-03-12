package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.error.ClientNotFoundException;
import lombok.AccessLevel;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DefaultOAuth2ClientDetailsService implements OAuth2ClientDetailsService {

    @Getter(AccessLevel.PROTECTED)
    private final OAuth2ClientRepository repository;

    @Autowired
    public DefaultOAuth2ClientDetailsService(OAuth2ClientRepository repository) {
        this.repository = repository;
    }

    @Override
    public OAuth2ClientDetails loadClientDetailsByClientId(String clientId) {
        return repository.findByClientId(new OAuth2ClientId(clientId))
                .map(DefaultOAuth2ClientDetails::of)
                .orElseThrow(() -> ClientNotFoundException.instance(clientId + " is not found"));
    }
}
