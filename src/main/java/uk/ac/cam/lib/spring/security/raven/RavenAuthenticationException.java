package uk.ac.cam.lib.spring.security.raven;

import org.springframework.security.core.AuthenticationException;


public class RavenAuthenticationException extends AuthenticationException {
    public RavenAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }

    public RavenAuthenticationException(String msg) {
        super(msg);
    }
}
