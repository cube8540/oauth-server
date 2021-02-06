package cube8540.oauth.authentication.oauth.scope.domain

import cube8540.oauth.authentication.security.AuthorityCode
import org.springframework.data.jpa.repository.JpaRepository

interface OAuth2ScopeRepository: JpaRepository<OAuth2Scope, AuthorityCode> {

    fun countByCode(scopeId: AuthorityCode): Long

    fun findByInitializeTrue(): List<OAuth2Scope>
}