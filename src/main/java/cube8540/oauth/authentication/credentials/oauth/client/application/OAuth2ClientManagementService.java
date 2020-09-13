package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface OAuth2ClientManagementService {

    Long countClient(String clientId);

    Page<OAuth2ClientDetails> loadClientDetails(String owner, Pageable pageable);

    OAuth2ClientDetails loadClientDetails(String clientId);

    OAuth2ClientDetails registerNewClient(OAuth2ClientRegisterRequest registerRequest);

    OAuth2ClientDetails modifyClient(String clientId, OAuth2ClientModifyRequest modifyRequest);

    OAuth2ClientDetails changeSecret(String clientId, OAuth2ChangeSecretRequest changeRequest);

    OAuth2ClientDetails removeClient(String clientId);

}
