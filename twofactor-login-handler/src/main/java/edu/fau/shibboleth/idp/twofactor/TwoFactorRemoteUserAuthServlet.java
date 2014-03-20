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
import static com.duosecurity.shibboleth.idp.twofactor.TwoFactorLoginServlet.AKEY_KEY;
import static com.duosecurity.shibboleth.idp.twofactor.TwoFactorLoginServlet.HOST_KEY;
import static com.duosecurity.shibboleth.idp.twofactor.TwoFactorLoginServlet.IKEY_KEY;
import static com.duosecurity.shibboleth.idp.twofactor.TwoFactorLoginServlet.SKEY_KEY;
import static com.duosecurity.shibboleth.idp.twofactor.TwoFactorLoginServlet.USER_SUBJECT_KEY;
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
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import java.util.Iterator;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

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

        String username = principalName;

        String duoResponse = request.getParameter(duoResponseAttribute);

        /* 
         * DUO
         */

        if (duoResponse != null) {
            // We have a Duo response, verify it.
            log.debug( "We have a Duo response, verify it");
            String ikey = (String) request.getSession().getAttribute(IKEY_KEY);
            String skey = (String) request.getSession().getAttribute(SKEY_KEY);
            String akey = (String) request.getSession().getAttribute(AKEY_KEY);
            // Remove Duo attributes, just in case the session will persist.
            request.getSession().removeAttribute(SKEY_KEY);
            request.getSession().removeAttribute(IKEY_KEY);
            request.getSession().removeAttribute(AKEY_KEY);

            String duoUsername = DuoWeb.verifyResponse(ikey, skey, akey, duoResponse);
            // Get the subject we stored in the session after authentication.
            Subject userSubject = (Subject) request.getSession().getAttribute(USER_SUBJECT_KEY);
            // Set authentication attributes if we find a principal
            // matching the Duo username; assume we were the only ones to
            // add a UsernamePrincpal.
            Set<UsernamePrincipal> principals = userSubject.getPrincipals(UsernamePrincipal.class);
            Iterator iter = principals.iterator();
            while (iter.hasNext()) {
                UsernamePrincipal principal = (UsernamePrincipal) iter.next();
                if (duoUsername.equals(principal.getName())) {
                    // Duo username matches the one we locally authed with,
                    // user is legit.
                    request.setAttribute(LoginHandler.SUBJECT_KEY, userSubject);
                    request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authenticationMethod);
                    request.getSession().removeAttribute(USER_SUBJECT_KEY);
                    log.debug( "Return to authentication engine");
                    AuthenticationEngine.returnToAuthenticationEngine(request, response);
                    return;
                }
            }
            // Something was fake, expired, or not matching.
            //AuthenticationEngine.returnToAuthenticationEngine(request, response);
            return;
        } else if (username == null) {
            // We don't have Duo response or user, first interaction.
            // let servlet run

            log.debug("Remote user identified as {} returning control back to authentication engine", principalName);
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
            return;

        } else {
            // We don't have a Duo response, we do have user/pass.
            // Send to Duo page only after verifying user/pass.
            request.setAttribute(LoginHandler.PRINCIPAL_KEY, new UsernamePrincipal(principalName));
            request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, authenticationMethod);
        
            String ikey = (String) request.getSession().getAttribute(IKEY_KEY);
            String skey = (String) request.getSession().getAttribute(SKEY_KEY);
            String akey = (String) request.getSession().getAttribute(AKEY_KEY);
            String host = (String) request.getSession().getAttribute(HOST_KEY);
            // Remove Duo attributes, just in case the session will persist.
            request.getSession().removeAttribute(HOST_KEY);
            log.debug("Remote user identified as {} redirecting to duo", principalName);

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
