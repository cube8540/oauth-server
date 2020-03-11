package cube8540.oauth.authentication.credentials.authority.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SecuredResourceRepository extends JpaRepository<SecuredResource, SecuredResourceId> {

    Long countByResourceId(SecuredResourceId resourceId);

}
