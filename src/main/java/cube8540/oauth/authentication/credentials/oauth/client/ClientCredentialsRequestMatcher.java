package cube8540.oauth.authentication.credentials.oauth.client;

import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class ClientCredentialsRequestMatcher implements RequestMatcher {

    private final String path;

    ClientCredentialsRequestMatcher(String path) {
        this.path = path;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return request.getRequestURI().endsWith(path);
    }
}
