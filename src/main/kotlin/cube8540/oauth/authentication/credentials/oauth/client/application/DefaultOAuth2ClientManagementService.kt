package cube8540.oauth.authentication.credentials.oauth.client.application

import cube8540.oauth.authentication.credentials.AuthorityCode
import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientNotFoundException
import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientOwner
import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientRegisterException
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientValidatorFactory
import cube8540.oauth.authentication.credentials.oauth.extractGrantType
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.net.URI

@Service
class DefaultOAuth2ClientManagementService(private val repository: OAuth2ClientRepository): OAuth2ClientManagementService {

    @set:[Autowired Qualifier("defaultOAuth2ClientValidatorFactory")]
    lateinit var validateFactory: OAuth2ClientValidatorFactory

    @set:[Autowired]
    lateinit var passwordEncoder: PasswordEncoder

    @Transactional(readOnly = true)
    override fun countClient(clientId: String): Long = repository.countByClientId(OAuth2ClientId(clientId))

    @Transactional(readOnly = true)
    override fun loadClientDetails(owner: String, pageable: Pageable): Page<OAuth2ClientDetails> = repository
        .findByOwner(ClientOwner(owner), pageable)
        .map(DefaultOAuth2ClientDetails::of)

    @Transactional(readOnly = true)
    override fun loadClientDetails(clientId: String): OAuth2ClientDetails = DefaultOAuth2ClientDetails.of(getClient(clientId))

    @Transactional
    override fun registerNewClient(registerRequest: OAuth2ClientRegisterRequest): OAuth2ClientDetails {
        if (countClient(registerRequest.clientId) > 0) {
            throw ClientRegisterException.existsIdentifier("${registerRequest.clientId} is exists")
        }

        val client = OAuth2Client(registerRequest.clientId, registerRequest.secret)
        client.clientName = registerRequest.clientName
        client.owner = registerRequest.clientOwner?.let { owner -> ClientOwner(owner) }
        registerRequest.grantTypes?.forEach { grant -> client.addGrantType(extractGrantType(grant)) }
        registerRequest.scopes?.forEach { scope -> client.addScope(AuthorityCode(scope)) }
        registerRequest.redirectUris?.forEach { uri -> client.addRedirectUri(URI.create(uri)) }
        registerRequest.accessTokenValiditySeconds?.run(client::setAccessTokenValidity)
        registerRequest.refreshTokenValiditySeconds?.run(client::setRefreshTokenValidity)

        client.validate(validateFactory)
        client.encrypted(passwordEncoder)
        return DefaultOAuth2ClientDetails.of(repository.save(client))
    }

    @Transactional
    override fun modifyClient(clientId: String, modifyRequest: OAuth2ClientModifyRequest): OAuth2ClientDetails {
        val client = getClient(clientId)

        client.clientName = modifyRequest.clientName
        modifyRequest.removeRedirectUris?.forEach { uri -> client.removeRedirectUri(URI.create(uri)) }
        modifyRequest.newRedirectUris?.forEach { uri -> client.addRedirectUri(URI.create(uri)) }
        modifyRequest.removeGrantTypes?.forEach { grant -> client.removeGrantType(extractGrantType(grant)) }
        modifyRequest.newGrantTypes?.forEach { grant -> client.addGrantType(extractGrantType(grant)) }
        modifyRequest.removeScopes?.forEach { scope -> client.removeScope(AuthorityCode(scope)) }
        modifyRequest.newScopes?.forEach { scope -> client.addScope(AuthorityCode(scope)) }
        modifyRequest.accessTokenValiditySeconds?.run(client::setAccessTokenValidity)
        modifyRequest.refreshTokenValiditySeconds?.run(client::setRefreshTokenValidity)

        client.validate(validateFactory)
        return DefaultOAuth2ClientDetails.of(repository.save(client))
    }

    @Transactional
    override fun changeSecret(clientId: String, changeRequest: OAuth2ChangeSecretRequest): OAuth2ClientDetails {
        val client = getClient(clientId)

        client.changeSecret(changeRequest.existsSecret, changeRequest.newSecret, passwordEncoder)
        client.validate(validateFactory)
        client.encrypted(passwordEncoder)

        return DefaultOAuth2ClientDetails.of(repository.save(client))
    }

    @Transactional
    override fun removeClient(clientId: String): OAuth2ClientDetails {
        val client = getClient(clientId)

        repository.delete(client)
        return DefaultOAuth2ClientDetails.of(client)
    }

    private fun getClient(clientId: String) = repository
        .findByClientId(OAuth2ClientId(clientId))
        .orElseThrow { ClientNotFoundException.instance("$clientId is not found") }
}