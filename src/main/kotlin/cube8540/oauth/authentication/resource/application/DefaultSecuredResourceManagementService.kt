package cube8540.oauth.authentication.resource.application

import cube8540.oauth.authentication.resource.domain.*
import cube8540.oauth.authentication.resource.domain.ResourceNotFoundException.Companion.instance
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.net.URI

@Service
class DefaultSecuredResourceManagementService @Autowired constructor(private val repository: SecuredResourceRepository): SecuredResourceManagementService {

    @set:[Autowired Qualifier("defaultSecuredResourceValidatorFactory")]
    lateinit var validatorFactory: SecuredResourceValidatorFactory

    @Transactional
    override fun registerNewResource(registerRequest: SecuredResourceRegisterRequest): SecuredResourceDetails {
        if (count(registerRequest.resourceId) > 0) {
            throw ResourceRegisterException.existsIdentifier("${registerRequest.resourceId} is already exists")
        }

        val resource = SecuredResource(SecuredResourceId(registerRequest.resourceId),
            URI.create(registerRequest.resource), ResourceMethod.of(registerRequest.method))
        registerRequest.authorities?.forEach { resource.addAuthority(it.authority) }
        resource.validation(validatorFactory)
        return DefaultSecuredResourceDetails.of(repository.save(resource))
    }

    @Transactional
    override fun modifyResource(resourceId: String, modifyRequest: SecuredResourceModifyRequest): SecuredResourceDetails {
        val resource = getResource(resourceId)

        resource.changeResourceInfo(URI.create(modifyRequest.resource), ResourceMethod.of(modifyRequest.method))
        modifyRequest.removeAuthorities?.forEach { resource.removeAuthority(it.authority) }
        modifyRequest.newAuthorities?.forEach { resource.addAuthority(it.authority) }
        resource.validation(validatorFactory)
        return DefaultSecuredResourceDetails.of(repository.save(resource))
    }

    @Transactional
    override fun removeResource(resourceId: String): SecuredResourceDetails {
        val resource = getResource(resourceId)

        repository.delete(resource)
        return DefaultSecuredResourceDetails.of(resource)
    }

    @Transactional(readOnly = true)
    override fun count(resourceId: String): Long = repository.countByResourceId(SecuredResourceId(resourceId))

    @Transactional(readOnly = true)
    override fun getResources(): List<SecuredResourceEntry> =
        repository.findAll().map(SecuredResourceEntry::of).toList()

    private fun getResource(resourceId: String): SecuredResource =
        repository.findById(SecuredResourceId(resourceId))
            .orElseThrow { instance("$resourceId is not found") }
}