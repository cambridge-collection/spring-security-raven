package uk.ac.cam.lib.spring.security.raven;

/**
 * An exception raised when a Raven response contains a non-200 status code.
 */
public class BadStatusRavenAuthenticationException extends RavenAuthenticationException {
    private final int status;

    public BadStatusRavenAuthenticationException(int status, Throwable t) {
        super(String.format(
            "Response contained unsuccessful status: %d", status), t);

        this.status = status;
    }

    public BadStatusRavenAuthenticationException(int status) {
        this(status, null);
    }

    public int getStatus() {
        return this.status;
    }
}
