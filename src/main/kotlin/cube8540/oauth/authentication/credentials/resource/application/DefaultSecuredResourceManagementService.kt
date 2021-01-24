package cube8540.oauth.authentication.credentials.resource.application

import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod
import cube8540.oauth.authentication.credentials.resource.domain.ResourceNotFoundException.Companion.instance
import cube8540.oauth.authentication.credentials.resource.domain.ResourceRegisterException
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceId
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceRepository
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceValidatorFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.net.URI
import java.util.stream.Collectors

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
        registerRequest.authorities?.forEach { auth -> resource.addAuthority(auth.authority) }
        resource.validation(validatorFactory)
        return DefaultSecuredResourceDetails.of(repository.save(resource))
    }

    @Transactional
    override fun modifyResource(resourceId: String, modifyRequest: SecuredResourceModifyRequest): SecuredResourceDetails {
        val resource = getResource(resourceId)

        resource.changeResourceInfo(URI.create(modifyRequest.resource), ResourceMethod.of(modifyRequest.method))
        modifyRequest.removeAuthorities?.forEach { auth -> resource.removeAuthority(auth.authority) }
        modifyRequest.newAuthorities?.forEach { auth -> resource.addAuthority(auth.authority) }
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
    override fun getResources(): List<SecuredResourceDetails> =
        repository.findAll().stream()
            .map { res -> DefaultSecuredResourceDetails.of(res) }
            .collect(Collectors.toList())

    private fun getResource(resourceId: String): SecuredResource =
        repository.findById(SecuredResourceId(resourceId))
            .orElseThrow { instance("$resourceId is not found") }
}