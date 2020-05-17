package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientOwner;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientValidatePolicy;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientAuthorizationException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientRegisterException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import lombok.Setter;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.util.Optional;

public class DefaultOAuth2ClientManagementService extends DefaultOAuth2ClientDetailsService implements OAuth2ClientManagementService {

    @Setter
    private OAuth2ClientValidatePolicy validatePolicy;

    @Setter
    private PasswordEncoder passwordEncoder;

    public DefaultOAuth2ClientManagementService(OAuth2ClientRepository repository) {
        super(repository);
    }

    @Override
    public Long countClient(String clientId) {
        return getRepository().countByClientId(new OAuth2ClientId(clientId));
    }

    @Override
    public Page<OAuth2ClientDetails> loadClientDetails(Pageable pageable) {
        ClientOwner owner = new ClientOwner(SecurityContextHolder.getContext().getAuthentication().getName());
        return getRepository().findByOwner(owner, pageable).map(DefaultOAuth2ClientDetails::of);
    }

    @Override
    @Transactional
    public OAuth2ClientDetails registerNewClient(OAuth2ClientRegisterRequest registerRequest) {
        if (getRepository().countByClientId(new OAuth2ClientId(registerRequest.getClientId())) > 0) {
            throw ClientRegisterException.existsIdentifier(registerRequest.getClientId() + " is exists");
        }
        OAuth2Client client = new OAuth2Client(registerRequest.getClientId(), registerRequest.getSecret());

        client.setClientName(registerRequest.getClientName());
        client.setOwner(new ClientOwner(SecurityContextHolder.getContext().getAuthentication().getName()));
        Optional.ofNullable(registerRequest.getGrantTypes())
                .ifPresent(grantType -> grantType.forEach(grant -> client.addGrantType(OAuth2Utils.extractGrantType(grant))));
        Optional.ofNullable(registerRequest.getScopes())
                .ifPresent(scope -> scope.forEach(s -> client.addScope(new OAuth2ScopeId(s))));
        Optional.ofNullable(registerRequest.getRedirectUris())
                .ifPresent(redirectUri -> redirectUri.forEach(uri -> client.addRedirectUri(URI.create(uri))));

        client.validate(validatePolicy);
        client.encrypted(passwordEncoder);
        return DefaultOAuth2ClientDetails.of(getRepository().save(client));
    }

    @Override
    @Transactional
    public OAuth2ClientDetails modifyClient(String clientId, OAuth2ClientModifyRequest modifyRequest) {
        OAuth2Client client = getClient(clientId);
        ClientOwner authenticated = new ClientOwner(SecurityContextHolder.getContext().getAuthentication().getName());
        assertClientOwner(client, authenticated);
        client.setClientName(modifyRequest.getClientName());
        Optional.ofNullable(modifyRequest.getRemoveRedirectUris())
                .ifPresent(redirectUri -> redirectUri.forEach(uri -> client.removeRedirectUri(URI.create(uri))));
        Optional.ofNullable(modifyRequest.getNewRedirectUris())
                .ifPresent(redirectUri -> redirectUri.forEach(uri -> client.addRedirectUri(URI.create(uri))));
        Optional.ofNullable(modifyRequest.getRemoveGrantTypes())
                .ifPresent(grantType -> grantType.forEach(grant -> client.removeGrantType(OAuth2Utils.extractGrantType(grant))));
        Optional.ofNullable(modifyRequest.getNewGrantTypes())
                .ifPresent(grantType -> grantType.forEach(grant -> client.addGrantType(OAuth2Utils.extractGrantType(grant))));
        Optional.ofNullable(modifyRequest.getRemoveScopes())
                .ifPresent(scope -> scope.forEach(s -> client.removeScope(new OAuth2ScopeId(s))));
        Optional.ofNullable(modifyRequest.getNewScopes())
                .ifPresent(scope -> scope.forEach(s -> client.addScope(new OAuth2ScopeId(s))));

        client.validate(validatePolicy);
        return DefaultOAuth2ClientDetails.of(getRepository().save(client));
    }

    @Override
    @Transactional
    public OAuth2ClientDetails changeSecret(String clientId, OAuth2ChangeSecretRequest changeRequest) {
        OAuth2Client client = getClient(clientId);

        ClientOwner authenticated = new ClientOwner(SecurityContextHolder.getContext().getAuthentication().getName());
        assertClientOwner(client, authenticated);

        client.changeSecret(changeRequest.getExistsSecret(), changeRequest.getNewSecret(), passwordEncoder);
        client.validate(validatePolicy);
        client.encrypted(passwordEncoder);

        return DefaultOAuth2ClientDetails.of(getRepository().save(client));
    }

    @Override
    @Transactional
    public OAuth2ClientDetails removeClient(String clientId) {
        OAuth2Client client = getClient(clientId);

        ClientOwner authenticated = new ClientOwner(SecurityContextHolder.getContext().getAuthentication().getName());
        assertClientOwner(client, authenticated);

        getRepository().delete(client);
        return DefaultOAuth2ClientDetails.of(client);
    }

    private OAuth2Client getClient(String clientId) {
        return getRepository().findByClientId(new OAuth2ClientId(clientId))
                .orElseThrow(() -> ClientNotFoundException.instance(clientId + " is not found"));
    }

    private void assertClientOwner(OAuth2Client client, ClientOwner authenticated) {
        if (!client.getOwner().equals(authenticated)) {
            throw ClientAuthorizationException.invalidOwner("owner and authenticated user not matched");
        }
    }
}
