package cube8540.oauth.authentication.credentials.oauth.scope.domain

import cube8540.oauth.authentication.credentials.AuthorityCode
import org.springframework.data.jpa.repository.JpaRepository

interface OAuth2ScopeRepository: JpaRepository<OAuth2Scope, AuthorityCode> {

    fun countByCode(scopeId: AuthorityCode): Long
}