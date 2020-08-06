package cube8540.oauth.authentication.users.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Username> {

    Long countByUsername(Username username);
}
