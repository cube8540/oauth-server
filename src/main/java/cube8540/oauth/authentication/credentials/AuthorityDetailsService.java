package cube8540.oauth.authentication.credentials;

import java.util.Collection;

public interface AuthorityDetailsService {

    Collection<AuthorityDetails> loadAuthorityByAuthorityCodes(Collection<String> authorities);

}
