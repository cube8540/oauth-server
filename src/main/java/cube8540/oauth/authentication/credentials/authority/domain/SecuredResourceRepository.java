package cube8540.oauth.authentication.credentials.authority.domain;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SecuredResourceRepository extends JpaRepository<SecuredResource, SecuredResourceId> {

    Long countByResourceId(SecuredResourceId resourceId);

    @Override
    @EntityGraph(attributePaths = {"authorities"}, type = EntityGraph.EntityGraphType.LOAD)
    List<SecuredResource> findAll();

    @Override
    @EntityGraph(attributePaths = {"authorities"}, type = EntityGraph.EntityGraphType.LOAD)
    Optional<SecuredResource> findById(SecuredResourceId id);

}
