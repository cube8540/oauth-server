package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetailsService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface OAuth2ClientManagementService extends OAuth2ClientDetailsService {

    Long countClient(String clientId);

    Page<OAuth2ClientDetails> loadClientDetails(Pageable pageable);

    OAuth2ClientDetails registerNewClient(OAuth2ClientRegisterRequest registerRequest);

    OAuth2ClientDetails modifyClient(String clientId, OAuth2ClientModifyRequest modifyRequest);

    OAuth2ClientDetails changeSecret(String clientId, OAuth2ChangeSecretRequest changeRequest);

    OAuth2ClientDetails removeClient(String clientId);

}
