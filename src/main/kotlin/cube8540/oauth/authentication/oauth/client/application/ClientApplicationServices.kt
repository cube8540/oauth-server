package cube8540.oauth.authentication.oauth.client.application

import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable

interface OAuth2ClientManagementService {

    fun countClient(clientId: String): Long

    fun loadClientDetails(owner: String, pageable: Pageable): Page<OAuth2ClientEntry>

    fun loadClientDetails(clientId: String): OAuth2ClientDetails

    fun registerNewClient(registerRequest: OAuth2ClientRegisterRequest): OAuth2ClientDetails

    fun modifyClient(clientId: String, modifyRequest: OAuth2ClientModifyRequest): OAuth2ClientDetails

    fun changeSecret(clientId: String, changeRequest: OAuth2ChangeSecretRequest): OAuth2ClientDetails

    fun removeClient(clientId: String): OAuth2ClientDetails
}