package cube8540.oauth.authentication.credentials.authority;

import java.util.Collection;

public interface AuthorityDetailsService {

    AuthorityDetails getAuthority(String code);

    Collection<AuthorityDetails> getAuthorities();

}
