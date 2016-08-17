package uk.ac.cam.lib.spring.security.raven;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;
import uk.ac.cam.ucs.webauth.WebauthRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;


public class RavenAuthenticationEntryPoint implements AuthenticationEntryPoint {

    public static final URI DEFAULT_RAVEN_AUTH_URL = URI.create(
        "https://raven.cam.ac.uk/auth/authenticate.html");

    private final URI ravenAuthUri;
    private final RavenRequestCreator requestCreator;

    public RavenAuthenticationEntryPoint(RavenRequestCreator requestCreator) {
        this(requestCreator, DEFAULT_RAVEN_AUTH_URL);
    }

    public RavenAuthenticationEntryPoint(RavenRequestCreator requestCreator,
                                         URI ravenAuthUri) {
        Assert.notNull(requestCreator);
        Assert.notNull(ravenAuthUri);

        this.requestCreator = requestCreator;
        this.ravenAuthUri = ravenAuthUri;
    }

    public RavenRequestCreator getRequestCreator() {
        return this.requestCreator;
    }

    public URI getRavenAuthUri() {
        return this.ravenAuthUri;
    }

    @Override
    public void commence(
        HttpServletRequest request, HttpServletResponse response,
        AuthenticationException authException)
        throws IOException, ServletException {

        WebauthRequest ravenRequest = getRequestCreator()
            .createLoginRequest(request);

        response.sendRedirect(getLoginUrl(ravenRequest).toString());
    }

    private URI getLoginUrl(WebauthRequest request) {
        return UriComponentsBuilder.fromUri(getRavenAuthUri())
            .replaceQuery(request.toQString().replace("+", "%20"))
            .build(true)
            .toUri();
    }
}
