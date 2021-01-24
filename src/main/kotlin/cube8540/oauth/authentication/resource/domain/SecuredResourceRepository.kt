package cube8540.oauth.authentication.resource.domain

import org.springframework.data.jpa.repository.EntityGraph
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*

interface SecuredResourceRepository: JpaRepository<SecuredResource, SecuredResourceId> {

    fun countByResourceId(resourceId: SecuredResourceId): Long

    @EntityGraph(attributePaths = ["authorities"], type = EntityGraph.EntityGraphType.LOAD)
    override fun findAll(): MutableList<SecuredResource>

    @EntityGraph(attributePaths = ["authorities"], type = EntityGraph.EntityGraphType.LOAD)
    override fun findById(id: SecuredResourceId): Optional<SecuredResource>

}