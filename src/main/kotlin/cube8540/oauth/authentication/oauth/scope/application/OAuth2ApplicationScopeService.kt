package cube8540.oauth.authentication.oauth.scope.application

import cube8540.oauth.authentication.oauth.scope.domain.OAuth2Scope
import cube8540.oauth.authentication.oauth.scope.domain.OAuth2ScopeRepository
import cube8540.oauth.authentication.oauth.scope.domain.ScopeNotFoundException
import cube8540.oauth.authentication.oauth.scope.domain.ScopeRegisterException
import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.security.AuthorityDetails
import cube8540.oauth.authentication.security.AuthorityDetailsService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class OAuth2ApplicationScopeService
@Autowired
constructor(private val repository: OAuth2ScopeRepository):
    OAuth2ScopeDetailsService, OAuth2ScopeManagementService, AuthorityDetailsService {

    @Transactional(readOnly = true)
    override fun countByScopeId(scopeId: String): Long = repository.countByCode(AuthorityCode(scopeId))

    @Transactional(readOnly = true)
    override fun loadScopes(): Collection<OAuth2ScopeDetails> {

        return repository.findAll()
            .map { OAuth2ScopeDetails.of(it) }
    }

    @Transactional
    override fun registerNewScope(registerRequest: OAuth2ScopeRegisterRequest): OAuth2ScopeDetails {
        if (countByScopeId(registerRequest.scopeId) > 0) {
            throw ScopeRegisterException.existsIdentifier("${registerRequest.scopeId} is exists")
        }

        val scope = OAuth2Scope(registerRequest.scopeId, registerRequest.description)
        return OAuth2ScopeDetails.of(repository.save(scope))
    }

    @Transactional
    override fun modifyScope(scopeId: String, modifyRequest: OAuth2ScopeModifyRequest): OAuth2ScopeDetails {
        val scope = getScope(scopeId)

        scope.description = modifyRequest.description
        return OAuth2ScopeDetails.of(repository.save(scope))
    }

    @Transactional
    override fun removeScope(scopeId: String): OAuth2ScopeDetails {
        val scope = getScope(scopeId)

        repository.delete(scope)
        return OAuth2ScopeDetails.of(scope)
    }

    @Transactional(readOnly = true)
    override fun loadAuthorityByAuthorityCodes(authorities: Collection<String>): Collection<AuthorityDetails> {
        val scopeIn = authorities.map { AuthorityCode(it) }

        return repository.findAllById(scopeIn)
            .map { OAuth2ScopeDetails.of(it) }
    }

    @Transactional(readOnly = true)
    override fun loadInitializeAuthority(): Collection<AuthorityDetails> = repository
        .findByInitializeTrue()
        .map { OAuth2ScopeDetails.of(it) }

    private fun getScope(scopeId: String): OAuth2Scope = repository
        .findById(AuthorityCode(scopeId))
        .orElseThrow { ScopeNotFoundException.instance(scopeId) }
}