package cube8540.oauth.authentication.resource.application

interface SecuredResourceReadService {

    fun count(resourceId: String): Long

    fun getResources(): List<SecuredResourceDetails>
}

interface SecuredResourceManagementService: SecuredResourceReadService {

    fun registerNewResource(registerRequest: SecuredResourceRegisterRequest): SecuredResourceDetails

    fun modifyResource(resourceId: String, modifyRequest: SecuredResourceModifyRequest): SecuredResourceDetails

    fun removeResource(resourceId: String): SecuredResourceDetails
}