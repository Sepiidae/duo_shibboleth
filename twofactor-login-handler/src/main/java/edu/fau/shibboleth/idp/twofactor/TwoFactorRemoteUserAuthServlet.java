/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.fau.shibboleth.idp.twofactor;

import com.duosecurity.DuoWeb;
import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;

/**
 * Extracts the REMOTE_USER and places it in a request attribute to be used by
 * the authentication engine.
 *
 * By default, this Servlet assumes that the authentication method
 * <code>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</code>
 * to be returned to the authentication engine. This can be override by setting
 * the servlet configuration parameter
 * <code>authnMethod</code>.
 */
public class TwoFactorRemoteUserAuthServlet extends HttpServlet {

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = -6153665874235557534L;
    /**
     * Class logger.
     */
    private final Logger log = LoggerFactory.getLogger(TwoFactorRemoteUserAuthServlet.class);
    /**
     * The authentication method returned to the authentication engine.
     */
    private String authenticationMethod;
    /**
     * Duo authentication page name.
     */
    private String duoPage = "duo.jsp";
    /**
     * init-param which can be passed to the servlet to override the default Duo
     * authentication page.
     */
    private final String duoPageInitParam = "duoPage";
    /**
     * HTTP request parameter containing the response returned by Duo.
     */
    private final String duoResponseAttribute = "sig_response";
    /**
     * the key in a HttpSession where user subjects are stored.
     */
    public static final String USER_SUBJECT_KEY = "duo.usersubject";
    /**
     * keys in a HttpSevletRequest where Duo attributes are stored.
     */
    public static final String SKEY_KEY = "duo.skey";
    public static final String IKEY_KEY = "duo.ikey";
    public static final String AKEY_KEY = "duo.akey";
    public static final String HOST_KEY = "duo.host";

    /**
     * {@inheritDoc}
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        if (getInitParameter(duoPageInitParam) != null) {
            duoPage = getInitParameter(duoPageInitParam);
        }
        if (!duoPage.startsWith("/")) {
            duoPage = "/" + duoPage;
        }

        String method =
                DatatypeHelper.safeTrimOrNullString(config.getInitParameter(LoginHandler.AUTHENTICATION_METHOD_KEY));
        if (method != null) {
            authenticationMethod = method;
        } else {
            authenticationMethod = AuthnContext.PPT_AUTHN_CTX;
        }
    }

    /**
     * {@inheritDoc}
     */
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {

        String principalName = DatatypeHelper.safeTrimOrNullString(request.getRemoteUser());
        log.debug("Principal name from remote service is {} ", principalName);
        String username = principalName;

        String duoResponse = request.getParameter(duoResponseAttribute);

        /* 
         * DUO
         */

        if (duoResponse != null) {
            // We have a Duo response, verify it.
            log.debug("We have a Duo response, verify it");
            String ikey = (String) request.getSession().getAttribute(IKEY_KEY);
            String skey = (String) request.getSession().getAttribute(SKEY_KEY);
            String akey = (String) request.getSession().getAttribute(AKEY_KEY);
            // Remove Duo attributes, just in case the session will persist.
            request.getSession().removeAttribute(SKEY_KEY);
            request.getSession().removeAttribute(IKEY_KEY);
            request.getSession().removeAttribute(AKEY_KEY);



            String duoUsername = DuoWeb.verifyResponse(ikey, skey, akey, duoResponse);
            // Get the subject we stored in the session after authentication.

            log.debug("We have a Duo response, confirming principle matches, response is for {} and it should be for {}", duoUsername, principalName);

            if (duoUsername.equals(principalName)) {
                // Duo username matches the one we locally authed with,
                // user is legit.
                request.setAttribute(LoginHandler.PRINCIPAL_KEY, new UsernamePrincipal(principalName));
                request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authenticationMethod);

                log.debug("Return to authentication engine");
                AuthenticationEngine.returnToAuthenticationEngine(request, response);
                return;
            }
            log.debug("Something was fake, expired, or not matching, returning error");
            // Something was fake, expired, or not matching.
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
            return;
        } else {
            if (principalName == null) {
                // if we have a null principalName something is very wrong
                // in this case we will let authentication fail
                log.debug("Discovered null principalName, this cannot happen with RemoteUser authentication, throw error");
                AuthenticationEngine.returnToAuthenticationEngine(request, response);
                return;

            }

            // We don't have a Duo response, we do have user.
            // Send to Duo page only after verifying user/pass.
            request.setAttribute(LoginHandler.PRINCIPAL_KEY, new UsernamePrincipal(principalName));
            request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authenticationMethod);

            String ikey = (String) request.getSession().getAttribute(IKEY_KEY);
            String skey = (String) request.getSession().getAttribute(SKEY_KEY);
            String akey = (String) request.getSession().getAttribute(AKEY_KEY);
            String host = (String) request.getSession().getAttribute(HOST_KEY);
            // Remove Duo attributes, just in case the session will persist.
            request.getSession().removeAttribute(HOST_KEY);

            log.debug("Remote user identified as {} attempting to signing duo request", principalName);

            request.setAttribute("host", host);
            String sigRequest = DuoWeb.signRequest(ikey, skey, akey, username);
            request.setAttribute("sigRequest", sigRequest);
           

            redirectToDuoPage(request, response);
            return;
        }




    }

    /**
     * Sends the user to a page with an actionUrl attribute pointing back.
     *
     * @param path path to page
     * @param request current request
     * @param response current response
     */
    protected void redirectToPage(String path, HttpServletRequest request, HttpServletResponse response) {

        StringBuilder actionUrlBuilder = new StringBuilder();
        if (!"".equals(request.getContextPath())) {
            actionUrlBuilder.append(request.getContextPath());
        }
        actionUrlBuilder.append(request.getServletPath());
        request.setAttribute("actionUrl", actionUrlBuilder.toString());

        try {
            request.getRequestDispatcher(path).forward(request, response);
            log.debug("Redirecting to page {}", path);
        } catch (IOException ex) {
            log.error("Unable to redirect to page.", ex);
        } catch (ServletException ex) {
            log.error("Unable to redirect to page.", ex);
        }
    }

    /**
     * Sends the user to the Duo authentication page.
     *
     * @param request current request
     * @param response current response
     */
    protected void redirectToDuoPage(HttpServletRequest request, HttpServletResponse response) {
        redirectToPage(duoPage, request, response);
    }
}
