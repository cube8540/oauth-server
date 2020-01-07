package cube8540.oauth.authentication.credentials.oauth.client.provider;

import cube8540.oauth.authentication.credentials.oauth.OAuth2BadClientCredentialsException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ClientCredentialsEndpointFilter extends AbstractAuthenticationProcessingFilter {

    private AuthenticationEntryPoint entryPoint;
    private boolean onlyPost = false;

    public ClientCredentialsEndpointFilter(String endpoint) {
        super(endpoint);
        setRequiresAuthenticationRequestMatcher(new ClientCredentialsRequestMatcher(endpoint));
    }

    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet();
        // 아무 행동도 하지 않고 다음 필터로 넘어가도록 설정한다.
        setAuthenticationSuccessHandler((request, response, authentication) -> {});
        setAuthenticationFailureHandler((request, response, exception) -> {
            if (exception instanceof BadCredentialsException) {
                exception = new OAuth2BadClientCredentialsException(exception.getMessage());
            }
            entryPoint.commence(request, response, exception);
        });
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        if (onlyPost && !request.getMethod().equalsIgnoreCase("POST")) {
            throw new HttpRequestMethodNotSupportedException(request.getMethod(), new String[] {"POST"});
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return authentication;
        }
        String clientId = request.getParameter("client_id");
        String clientSecret = request.getParameter("client_secret");

        if (clientId == null) {
            throw new BadCredentialsException("no client credentials presented");
        }
        return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(clientId, clientSecret));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);
    }

    public void setEntryPoint(AuthenticationEntryPoint entryPoint) {
        this.entryPoint = entryPoint;
    }

    public void setOnlyPost(boolean onlyPost) {
        this.onlyPost = onlyPost;
    }
}
