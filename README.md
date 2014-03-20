# Overview

**duo_shibboleth** - Duo two-factor authentication components for Shibboleth

What is here:

* `twofactor-login-handler` - Duo two-factor authentication login handler for
Shibboleth 2


Installation:

	* git pull https://github.com/sepiidae/duo_shibboleth.git duo_shibboleth
	* cd twofactor-login-handler
	* mvn package
	* cp target/twofactor-login-handler-0.2.jar ~/$SHIB_INSTALLER/lib/
	* cd $SHIB_INSTALLER
	
Add the following to $SHIB_INSTALLEr/src/main/webapp/WEB-INF/web.xml

 <servlet>
    <servlet-name>TwoFactorRemoteLoginHandler</servlet-name>
    <servlet-class>edu.fau.shibboleth.idp.twofactor.TwoFactorRemoteUserAuthServlet</servlet-class>
    <init-param>
        <param-name>authnMethod</param-name>
        <param-value>urn:fau.edu:ac:classes:PasswordProtectedTransport:duo</param-value>
    </init-param>
    <load-on-startup>5</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>TwoFactorRemoteLoginHandler</servlet-name>
    <url-pattern>/Authn/DuoRemoteUser</url-pattern>
  </servlet-mapping>

* Configure your RemoteUser service to protect /Authn/DuoRemoteUser 

Example CAS:
<filter>
  <filter-name>CAS Authentication Filter</filter-name>
  <filter-class>
      org.jasig.cas.client.authentication.AuthenticationFilter
  </filter-class>
  <init-param>
    <param-name>casServerLoginUrl</param-name>
    <param-value>https://sso.sepiidae.com/cas/login</param-value>
  </init-param>
  <init-param>
        <param-name>serverName</param-name>
        <param-value>idp.sepiidae.com</param-value>
   </init-param>
</filter>

<filter-mapping>
  <filter-name>CAS Authentication Filter</filter-name>
  <url-pattern>/Authn/RemoteUser</url-pattern>
</filter-mapping>
<filter-mapping>
  <filter-name>CAS Authentication Filter</filter-name>
  <url-pattern>/Authn/DuoRemoteUser</url-pattern>
</filter-mapping>

<filter>
  <filter-name>CAS Validation Filter</filter-name>
  <filter-class>
    org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter
  </filter-class>
  <init-param>
    <param-name>casServerUrlPrefix</param-name>
    <param-value>https://sso.sepiidae.com/cas/login</param-value>
  </init-param>
  <init-param>
    <param-name>redirectAfterValidation</param-name>
    <param-value>true</param-value>
  </init-param>
  <init-param>
          <param-name>serverName</param-name>
          <param-value>idp.sepiidae.com</param-value>
  </init-param>

</filter>

<filter-mapping>
  <filter-name>CAS Validation Filter</filter-name>
  <url-pattern>/Authn/RemoteUser</url-pattern>
</filter-mapping>
<filter-mapping>
  <filter-name>CAS Validation Filter</filter-name>
  <url-pattern>/Authn/DuoRemoteUser</url-pattern>
</filter-mapping>

<filter>
  <filter-name>CAS HttpServletRequest Wrapper Filter</filter-name>
  <filter-class>
    org.jasig.cas.client.util.HttpServletRequestWrapperFilter
  </filter-class>
</filter>
<filter-mapping>
  <filter-name>CAS HttpServletRequest Wrapper Filter</filter-name>
  <url-pattern>/Authn/RemoteUser</url-pattern>
</filter-mapping>
<filter-mapping>
  <filter-name>CAS HttpServletRequest Wrapper Filter</filter-name>
  <url-pattern>/Authn/DuoRemoteUser</url-pattern>
</filter-mapping>


* Configure your login handlers 
** This example configures Shibboleth to only respond to urn:fau.edu:ac:classes:PasswordProtectedTransport:duo authentication requests.

<!-- Login Handlers -->
<!-- Standard login handler, for PasswordProtectedTransport and unspecified -->
<ph:LoginHandler xsi:type="ph:RemoteUser">
   <ph:AuthenticationMethod>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</ph:AuthenticationMethod>
   <ph:AuthenticationMethod>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</ph:AuthenticationMethod>
</ph:LoginHandler>

<!-- DUO login handler, for duo requestso only -->
<!--  Username/password login handler  -->
<ph:LoginHandler 
	xsi:type="twofactor:TwoFactorLogin" 
	remoteUser="true" 
	authenticationServletURL="/Authn/DuoRemoteUser"
	skey="BJPmSeBFgcuIlZpkHRAwiZHVWxM5tTQUeAojrEZA" ikey="DIRQ0JX71OYE0YMI7SW7" akey="jdfjk3r8u9df39834289fd8vd89r8234ihdfhjdfsjh2r3jh23uidfuh32h2r3wea9032hj3c034fa2" host="api-3c034fa2.duosecurity.com">
	<ph:AuthenticationMethod>urn:fau.edu:ac:classes:PasswordProtectedTransport:duo</ph:AuthenticationMethod>
</ph:LoginHandler>

