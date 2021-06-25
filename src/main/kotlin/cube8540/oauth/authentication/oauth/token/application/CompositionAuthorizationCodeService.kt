package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.security.AuthorizationCode
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest
import cube8540.oauth.authentication.oauth.security.OAuth2AuthorizationCodeGenerator
import cube8540.oauth.authentication.oauth.token.domain.AuthorizationCodeGenerator
import cube8540.oauth.authentication.oauth.token.domain.AuthorizationCodeRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCode
import cube8540.oauth.authentication.oauth.token.infra.DefaultAuthorizationCodeGenerator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class CompositionAuthorizationCodeService @Autowired constructor(
    private val codeRepository: AuthorizationCodeRepository
): OAuth2AuthorizationCodeConsumer, OAuth2AuthorizationCodeGenerator {

    var codeGenerator: AuthorizationCodeGenerator = DefaultAuthorizationCodeGenerator()

    @Transactional
    override fun generateNewAuthorizationCode(request: AuthorizationRequest): AuthorizationCode {
        val authorizationCode = OAuth2AuthorizationCode(codeGenerator)

        authorizationCode.setAuthorizationRequest(request)
        codeRepository.save(authorizationCode)
        return AuthorizationCode(authorizationCode.code)
    }

    @Transactional
    override fun consume(code: String): OAuth2AuthorizationCode? {
        val authorizationCode = codeRepository.findById(code)

        authorizationCode.ifPresent(codeRepository::delete)
        return authorizationCode.orElse(null)
    }
}