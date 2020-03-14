package cube8540.oauth.authentication.credentials.authority.domain;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AuthorityRepository extends JpaRepository<Authority, AuthorityCode> {

    Long countByCode(AuthorityCode code);

    @EntityGraph(attributePaths = {"accessibleResources"}, type = EntityGraph.EntityGraphType.LOAD)
    List<Authority> findByBasicTrue();

    @Override
    @EntityGraph(attributePaths = {"accessibleResources"}, type = EntityGraph.EntityGraphType.LOAD)
    List<Authority> findAll();

    @Override
    @EntityGraph(attributePaths = {"accessibleResources"}, type = EntityGraph.EntityGraphType.LOAD)
    Optional<Authority> findById(AuthorityCode code);

}
