package uk.ac.cam.lib.spring.security.raven;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.util.UriUtils;
import uk.ac.cam.lib.spring.security.raven.vedorised.SavedRequestAwareWrapper;
import uk.ac.cam.ucs.webauth.WebauthException;
import uk.ac.cam.ucs.webauth.WebauthRequest;
import uk.ac.cam.ucs.webauth.WebauthResponse;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalField;
import java.util.Arrays;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Intercepts redirected requests from the Raven WLS which contain
 * an authentication response in the {@code WLS-Response} query string. A
 * {@link RavenAuthenticationToken} is created and passed on to our
 * {@link AuthenticationManager} to be checked for validity, presumably by an
 * instance of {@link RavenAuthenticationProvider}.
 */
public class RavenAuthenticationFilter
    extends AbstractAuthenticationProcessingFilter {

    public static final String RESPONSE_PARAMETER_NAME = "WLS-Response";

    private final RequestCache requestCache;
    private final RavenRequestCreator ravenRequestCreator;
    private final String responseParameterName;
    private final Clock clock;

    public RavenAuthenticationFilter(
        AuthenticationManager authenticationManager,
        RavenRequestCreator ravenRequestCreator, RequestCache requestCache) {

        this(authenticationManager, ravenRequestCreator, requestCache,
             AnyRequestMatcher.INSTANCE, Clock.systemUTC(),
             RESPONSE_PARAMETER_NAME);
    }

    public RavenAuthenticationFilter(
        AuthenticationManager authenticationManager,
        RavenRequestCreator ravenRequestCreator,
        RequestCache requestCache,
        RequestMatcher requiresAuthenticationRequestMatcher,
        Clock clock,
        String responseParameterName) {

        super(new AndRequestMatcher(
            requiresAuthenticationRequestMatcher,
            queryContainsResponseParamRequestMatcher(responseParameterName)));

        Assert.notNull(authenticationManager);
        Assert.notNull(ravenRequestCreator);
        Assert.notNull(requestCache);
        Assert.notNull(clock);
        Assert.hasText(responseParameterName);

        super.setAuthenticationManager(authenticationManager);
        this.ravenRequestCreator = ravenRequestCreator;
        this.requestCache = requestCache;
        this.clock = clock;
        this.responseParameterName = responseParameterName;
    }

    @Override
    public void setAuthenticationManager(
        AuthenticationManager authenticationManager) {

        throw new RuntimeException("Use the constructor argument");
    }

    static RequestMatcher queryContainsResponseParamRequestMatcher(
        String responseParameterName) {

        return r -> Optional.ofNullable(r.getQueryString())
            .map(query -> Arrays.stream(query.split("&"))
                .map(p -> {
                    try {
                        return UriUtils.decode(p.split("=", 2)[0], "UTF-8");
                    }
                    catch(UnsupportedEncodingException e) {
                        throw new AssertionError("Won't happen", e);
                    }
                })
                .anyMatch(p -> p.equals(responseParameterName))
            ).orElse(false);
    }

    public String getResponseParameterName() {
        return this.responseParameterName;
    }

    public RequestCache getRequestCache() {
        return this.requestCache;
    }

    public RavenRequestCreator getRavenRequestCreator() {
        return this.ravenRequestCreator;
    }

    public Clock getClock() {
        return this.clock;
    }

    /**
     * Get the HTTP request which was intercepted to trigger the Raven auth
     * cycle.
     *
     * @param currentRequest
     * @param currentResponse
     * @return The original request.
     */
    private Optional<HttpServletRequest> getInterceptedRequest(
        HttpServletRequest currentRequest,
        HttpServletResponse currentResponse) {

        // Can't use getRequestCache().getMatchingRequest() because it removes
        // the entry from the cache, which would prevent the auth success
        // handler redirecting to the original page.
        return Optional.ofNullable(getRequestCache()
                .getRequest(currentRequest, currentResponse))
            .map(sr -> new SavedRequestAwareWrapper(sr, currentRequest));
    }

    private String getAuthResponse(HttpServletRequest request) {
        String response = ServletRequestUtils.getStringParameter(
            request, this.getResponseParameterName(), null);

        if(response == null)
            throw new BadCredentialsException(
                "Request contained no query parameter named: " +
                    this.getResponseParameterName());

        return response;
    }

    @Override
    public Authentication attemptAuthentication(
        HttpServletRequest request,
        HttpServletResponse response)
        throws AuthenticationException, IOException, ServletException {

        Instant now = getClock().instant();

        WebauthResponse authResponse;
        try {
            authResponse = new WebauthResponse(
                getAuthResponse(request));
        } catch (WebauthException e) {
            throw new BadCredentialsException(
                "Invalid " + this.getResponseParameterName() + " parameter", e);
        }

        HttpServletRequest originalRequest =
            getInterceptedRequest(request, response)
                .orElseThrow(() -> new RavenAuthenticationException(
                    "Original request not in RequestCache"));

        WebauthRequest authRequest = getRavenRequestCreator()
            .createLoginRequest(originalRequest);

        if(authRequest == null)
            throw new IllegalStateException(
                "RavenRequestCreator.createLoginRequest() returned null");

        return this.getAuthenticationManager().authenticate(
            new RavenAuthenticationToken(authRequest, authResponse, now));
    }
}
