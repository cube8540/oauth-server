package cube8540.oauth.authentication.credentials.oauth.scope.application

import cube8540.oauth.authentication.credentials.AuthorityCode
import cube8540.oauth.authentication.credentials.AuthorityDetails
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository
import cube8540.oauth.authentication.credentials.oauth.scope.domain.ScopeNotFoundException
import cube8540.oauth.authentication.credentials.oauth.scope.domain.ScopeRegisterException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.stream.Collectors

@Service
class DefaultScopeDetailsService @Autowired constructor(private val repository: OAuth2ScopeRepository): OAuth2ScopeManagementService {

    @Transactional(readOnly = true)
    override fun countByScopeId(scopeId: String): Long = repository.countByCode(AuthorityCode(scopeId))

    @Transactional(readOnly = true)
    override fun loadScopes(): Collection<AuthorityDetails> = repository.findAll().stream()
        .map { authority -> DefaultOAuth2ScopeDetails.of(authority) }
        .collect(Collectors.toList())

    @Transactional
    override fun registerNewScope(registerRequest: OAuth2ScopeRegisterRequest): AuthorityDetails {
        if (countByScopeId(registerRequest.scopeId) > 0) {
            throw ScopeRegisterException.existsIdentifier("${registerRequest.scopeId} is exists")
        }

        val scope = OAuth2Scope(registerRequest.scopeId, registerRequest.description)
        return DefaultOAuth2ScopeDetails.of(repository.save(scope))
    }

    @Transactional
    override fun modifyScope(scopeId: String, modifyRequest: OAuth2ScopeModifyRequest): AuthorityDetails {
        val scope = getScope(scopeId)

        scope.description = modifyRequest.description
        return DefaultOAuth2ScopeDetails.of(repository.save(scope))
    }

    @Transactional
    override fun removeScope(scopeId: String): AuthorityDetails {
        val scope = getScope(scopeId)

        repository.delete(scope)
        return DefaultOAuth2ScopeDetails.of(scope)
    }

    @Transactional(readOnly = true)
    override fun loadAuthorityByAuthorityCodes(authorities: Collection<String>): Collection<AuthorityDetails> {
        val scopeIn = authorities.stream().map { authority -> AuthorityCode(authority) }.collect(Collectors.toList())

        return repository.findAllById(scopeIn).stream()
            .map { authority -> DefaultOAuth2ScopeDetails.of(authority) }
            .collect(Collectors.toList())
    }

    private fun getScope(scopeId: String): OAuth2Scope = repository
        .findById(AuthorityCode(scopeId))
        .orElseThrow { ScopeNotFoundException.instance(scopeId) }

}