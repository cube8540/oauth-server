package cube8540.oauth.authentication.oauth.client.application

import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.oauth.client.domain.ClientNotFoundException
import cube8540.oauth.authentication.oauth.client.domain.ClientOwner
import cube8540.oauth.authentication.oauth.client.domain.ClientRegisterException
import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientRepository
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientValidatorFactory
import cube8540.oauth.authentication.oauth.extractGrantType
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
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
    override fun loadClientDetails(owner: String, pageable: Pageable): Page<OAuth2ClientEntry> = repository
        .findByOwner(ClientOwner(owner), pageable)
        .map(OAuth2ClientEntry::of)

    @Transactional(readOnly = true)
    override fun loadClientDetails(clientId: String): OAuth2ClientDetails = DefaultOAuth2ClientDetails.of(getClient(clientId))

    @Transactional
    override fun registerNewClient(registerRequest: OAuth2ClientRegisterRequest): OAuth2ClientDetails {
        if (countClient(registerRequest.clientId) > 0) {
            throw ClientRegisterException.existsIdentifier("${registerRequest.clientId} is exists")
        }

        val client = OAuth2Client(registerRequest.clientId, registerRequest.secret)
        client.clientName = registerRequest.clientName
        client.owner = registerRequest.clientOwner?.let { ClientOwner(it) }
        registerRequest.grantTypes?.forEach { client.addGrantType(extractGrantType(it)) }
        registerRequest.scopes?.forEach { client.addScope(AuthorityCode(it)) }
        registerRequest.redirectUris?.forEach { client.addRedirectUri(URI.create(it)) }
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
        modifyRequest.removeRedirectUris?.forEach { client.removeRedirectUri(URI.create(it)) }
        modifyRequest.newRedirectUris?.forEach { client.addRedirectUri(URI.create(it)) }
        modifyRequest.removeGrantTypes?.forEach { client.removeGrantType(extractGrantType(it)) }
        modifyRequest.newGrantTypes?.forEach { client.addGrantType(extractGrantType(it)) }
        modifyRequest.removeScopes?.forEach { client.removeScope(AuthorityCode(it)) }
        modifyRequest.newScopes?.forEach { client.addScope(AuthorityCode(it)) }
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