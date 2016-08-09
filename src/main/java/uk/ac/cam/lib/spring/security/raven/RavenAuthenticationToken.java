package uk.ac.cam.lib.spring.security.raven;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;
import uk.ac.cam.ucs.webauth.WebauthRequest;
import uk.ac.cam.ucs.webauth.WebauthResponse;

import java.time.Instant;
import java.util.Collection;
import java.util.Optional;

public class RavenAuthenticationToken extends AbstractAuthenticationToken {

    private Optional<WebauthRequest> request;
    private Optional<WebauthResponse> response;
    private Optional<Instant>  responseReceivedTime;
    private final Object principal;

    static String getUsername(WebauthResponse response) {
        String username = response.get("principal");
        Assert.notNull(username); // May be empty though
        return username;
    }

    /**
     * Used to construct unauthenticated tokens from received Raven auth
     * responses.
     */
    public RavenAuthenticationToken(
        WebauthRequest request, WebauthResponse response,
        Instant responseReceivedTime) {

        this(request, response, responseReceivedTime,
             getUsername(response), null, false);

        Assert.notNull(request);
        Assert.notNull(response);
        Assert.notNull(responseReceivedTime);
    }

    /**
     * Used to create authenticated tokens with additional details once
     * validation of the auth response has been performed.
     */
    public RavenAuthenticationToken(
        WebauthRequest request, WebauthResponse response,
        Instant responseReceivedTime, Object principal,
        Collection<? extends GrantedAuthority> authorities) {

        this(request, response, responseReceivedTime, principal, authorities,
             true);
    }

    protected RavenAuthenticationToken(
        WebauthRequest request, WebauthResponse response,
        Instant responseReceivedTime, Object principal,
        Collection<? extends GrantedAuthority> authorities,
        boolean isAuthenticated) {

        super(authorities);

        int nullCount = (request == null ? 1 : 0) + (response == null ? 1 : 0) +
            (responseReceivedTime == null ? 1 : 0);

        Assert.isTrue(nullCount == 0 || nullCount == 3,
            "All of request, response and time must be present or not present");
        Assert.notNull(principal);

        this.request = Optional.ofNullable(request);
        this.response = Optional.ofNullable(response);
        this.responseReceivedTime = Optional.ofNullable(responseReceivedTime);
        this.principal = principal;
        super.setAuthenticated(isAuthenticated);
    }

    public RavenAuthenticationToken authenticate(
        Object principal, Collection<? extends GrantedAuthority> authorities) {

        if(this.isAuthenticated())
            throw new IllegalStateException("already authenticated");

        return new RavenAuthenticationToken(
            this.getRavenRequest().orElse(null),
            this.getRavenResponse().orElse(null),
            this.getResponseReceivedTime().orElse(null),
            principal, authorities);
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        throw new IllegalArgumentException(
            "Cannot set this token to trusted - use constructor");
    }

    @Override
    public Optional<WebauthResponse> getCredentials() {
        return this.getRavenResponse();
    }

    public Optional<WebauthRequest> getRavenRequest() {
        return this.request;
    }

    public Optional<WebauthResponse> getRavenResponse() {
        return this.response;
    }

    public Optional<Instant> getResponseReceivedTime() {
        return this.responseReceivedTime;
    }

    public boolean hasCredentials() {
        return this.getRavenRequest().isPresent() &&
            this.getRavenResponse().isPresent() &&
            this.getResponseReceivedTime().isPresent();
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();

        this.request = Optional.empty();
        this.response = Optional.empty();
        this.responseReceivedTime = Optional.empty();
    }
}
