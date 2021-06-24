package cube8540.oauth.authentication.resource.domain

import java.util.Optional
import org.springframework.data.jpa.repository.EntityGraph
import org.springframework.data.jpa.repository.JpaRepository

interface SecuredResourceRepository: JpaRepository<SecuredResource, SecuredResourceId> {

    fun countByResourceId(resourceId: SecuredResourceId): Long

    override fun findAll(): MutableList<SecuredResource>

    @EntityGraph(attributePaths = ["authorities"], type = EntityGraph.EntityGraphType.LOAD)
    override fun findById(id: SecuredResourceId): Optional<SecuredResource>

}