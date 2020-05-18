package cube8540.oauth.authentication.credentials.role.domain;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RoleRepository extends JpaRepository<Role, AuthorityCode> {

    Long countByCode(AuthorityCode code);

    List<Role> findByBasic(boolean basic);

}
