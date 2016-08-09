package uk.ac.cam.lib.spring.security.raven;

import uk.ac.cam.ucs.webauth.WebauthRequest;

import javax.servlet.http.HttpServletRequest;

public interface RavenRequestCreator {
    WebauthRequest createLoginRequest(HttpServletRequest request);


}
