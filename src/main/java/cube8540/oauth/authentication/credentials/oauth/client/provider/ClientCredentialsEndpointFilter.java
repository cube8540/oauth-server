package cube8540.oauth.authentication.credentials.oauth.client.provider;

import cube8540.oauth.authentication.credentials.oauth.error.BadClientCredentialsException;
import lombok.Setter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ClientCredentialsEndpointFilter extends AbstractAuthenticationProcessingFilter {

    @Setter
    private AuthenticationEntryPoint entryPoint;

    @Setter
    private boolean onlyPost = false;

    private AuthenticationConverter converter = new BasicAuthenticationConverter();

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
                exception = new BadClientCredentialsException(exception.getMessage());
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
        return getAuthenticationManager().authenticate(extractClientAuthentication(request));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);
    }

    private ClientCredentialsToken extractClientAuthentication(HttpServletRequest request) {
        Authentication basicAuthenticationToken = converter.convert(request);

        String clientId = basicAuthenticationToken != null ? basicAuthenticationToken.getPrincipal().toString() :
                request.getParameter("client_id");
        String clientSecret = basicAuthenticationToken != null ? basicAuthenticationToken.getCredentials().toString() :
                request.getParameter("client_secret");

        if (clientId == null) {
            throw new BadCredentialsException("no client credentials presented");
        }

        return new ClientCredentialsToken(clientId, clientSecret);
    }
}
