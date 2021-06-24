package cube8540.oauth.authentication.security

interface AuthorityDetailsService {

    fun loadAuthorityByAuthorityCodes(authorities: Collection<String>): Collection<AuthorityDetails>

    fun loadInitializeAuthority(): Collection<AuthorityDetails>
}