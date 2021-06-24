package cube8540.oauth.authentication.users.application

import cube8540.oauth.authentication.users.domain.ApprovalAuthority
import cube8540.oauth.authentication.users.domain.UserNotFoundException
import cube8540.oauth.authentication.users.domain.UserRepository
import cube8540.oauth.authentication.users.domain.UserValidatorFactory
import cube8540.oauth.authentication.users.domain.Username
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class DefaultUserApprovalAuthorityService @Autowired constructor(private val repository: UserRepository): UserApprovalAuthorityService {

    @set:[Autowired Qualifier("defaultApprovalAuthorityValidatorFactory")]
    lateinit var validatorFactory: UserValidatorFactory

    @Transactional(readOnly = true)
    override fun getApprovalAuthorities(username: String): Collection<ApprovalAuthority> {
        return repository.findById(Username(username))
            .map { it.approvalAuthorities ?: mutableSetOf() }
            .orElseThrow { UserNotFoundException.instance("$username is not found") }
    }

    @Transactional
    override fun grantApprovalAuthorities(username: String, authorities: Collection<ApprovalAuthority>): UserProfile {
        val user = repository.findById(Username(username))
            .orElseThrow { UserNotFoundException.instance("$username is not found") }

        authorities.forEach { user.addApprovalAuthority(it.clientId, it.scopeId) }
        user.validation(validatorFactory)

        return UserProfile(repository.save(user))
    }

    @Transactional
    override fun revokeApprovalAuthorities(username: String, authorities: Collection<ApprovalAuthority>): UserProfile {
        val user = repository.findById(Username(username))
            .orElseThrow { UserNotFoundException.instance("$username is not found") }

        authorities.forEach { user.revokeApprovalAuthority(it.clientId, it.scopeId) }

        return UserProfile(repository.save(user))
    }
}