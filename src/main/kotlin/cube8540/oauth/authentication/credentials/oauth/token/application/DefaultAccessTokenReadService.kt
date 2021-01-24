package cube8540.oauth.authentication.credentials.oauth.token.application

import cube8540.oauth.authentication.credentials.oauth.token.domain.AccessTokenDetailsWithClient
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenReadRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class DefaultAccessTokenReadService @Autowired constructor(
    private val repository: OAuth2AccessTokenReadRepository
): AccessTokenReadService {

    @Transactional(readOnly = true)
    override fun getAuthorizeAccessTokens(username: String): List<AccessTokenDetailsWithClient> =
        repository.readAccessTokenWithClientByUsername(username)
}