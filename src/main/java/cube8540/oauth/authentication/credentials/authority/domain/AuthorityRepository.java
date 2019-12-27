package cube8540.oauth.authentication.credentials.authority.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuthorityRepository extends JpaRepository<Authority, AuthorityCode> {

    List<Authority> findByBasicTrue();

}
