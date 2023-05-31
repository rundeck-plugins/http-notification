package com.rundeck.plugin

import com.dtolabs.rundeck.core.execution.workflow.steps.StepException
import com.dtolabs.rundeck.core.execution.workflow.steps.node.NodeStepException
import com.dtolabs.rundeck.core.plugins.Plugin
import com.dtolabs.rundeck.core.plugins.configuration.Describable
import com.dtolabs.rundeck.core.plugins.configuration.Description
import com.dtolabs.rundeck.core.plugins.configuration.StringRenderingConstants
import com.dtolabs.rundeck.plugins.ServiceNameConstants
import com.dtolabs.rundeck.plugins.descriptions.PluginDescription
import com.dtolabs.rundeck.plugins.notification.NotificationPlugin
import com.dtolabs.rundeck.plugins.util.DescriptionBuilder
import com.dtolabs.rundeck.plugins.util.PropertyBuilder
import org.apache.http.HttpEntity
import org.apache.http.client.config.RequestConfig
import org.apache.http.client.methods.RequestBuilder
import org.apache.http.entity.ByteArrayEntity
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import edu.ohio.ais.rundeck.HttpBuilder
import edu.ohio.ais.rundeck.util.OAuthClient

/**
 * Created by rundeck on 12/27/17.
 */
@Plugin(service= ServiceNameConstants.Notification, name=HttpNotificationPlugin.SERVICE_PROVIDER_NAME)
@PluginDescription(title=HttpNotificationPlugin.SERVICE_TITLE, description=HttpNotificationPlugin.SERVICE_PROVIDER_DESCRIPTION)
class HttpNotificationPlugin implements NotificationPlugin, Describable {

    private static final Logger log = LoggerFactory.getLogger(HttpNotificationPlugin.class);

    public static final String SERVICE_PROVIDER_NAME="HttpNotification"
    public static final String  SERVICE_TITLE="Http Notification"
    public static final String  SERVICE_PROVIDER_DESCRIPTION="Sends HTTP Notifications"
    public static final List<String> LIST_HTTP_METHOD = ["GET", "POST", "PUT", "DELETE"]
    public static final List<String> LIST_HTTP_CONTENT_TYPE = ["application/json", "application/xml", "text/html","application/x-www-form-urlencoded"]

    private static final Integer DEFAULT_TIMEOUT = 30*1000;

    static final String AUTH_NONE = "None"
    static final String AUTH_BASIC = "Basic"
    static final String AUTH_OAUTH2 = "OAuth 2.0"
    public static final String XML_FORMAT = "xml";
    public static final String JSON_FORMAT = "json";

    static final String HTTP_URL="remoteUrl"
    static final String HTTP_METHOD="method"
    static final String HTTP_HEADERS="headers"
    static final String HTTP_CONTENT_TYPE="contentType"
    static final String HTTP_BODY="body"
    static final String HTTP_TIMEOUT="timeout"
    static final String HTTP_NO_SSL_VERIFICATION="noSSLVerification"
    static final String HTTP_AUTHENTICATION="authentication"
    static final String HTTP_USERNAME="username"
    static final String HTTP_PASSWORD="password"
    static final String HTTP_AUTHTOKEN_ENDPOINT="oauthTokenEndpoint"
    static final String HTTP_AUTHTVALIDATE_ENDPOINT="oauthValidateEndpoint"
    static final String HTTP_PROXY_ENABLE="proxySettings"
    static final String HTTP_PROXY_IP="proxyIP"
    static final String HTTP_PROXY_PORT="proxyPort"

    static final String HTTP_PRINT="printResponseToFile"
    static final String HTTP_PRINT_FILE="file"

    /**
     * Synchronized map of all existing OAuth clients. This is indexed by
     * the Client ID and the token URL so that we can store and re-use access tokens.
     */
    final Map<String, OAuthClient> oauthClients = Collections.synchronizedMap(new HashMap<String, OAuthClient>());

    static Description DESCRIPTION = DescriptionBuilder.builder()
                .name(SERVICE_PROVIDER_NAME)
                .title(SERVICE_TITLE)
                .description(SERVICE_PROVIDER_DESCRIPTION)
                .property(PropertyBuilder.builder()
                                         .string(HTTP_URL)
                                         .title("Remote URL")
                                         .description("HTTP URL to which to make the request.")
                                         .required(true)
                                         .build())
                .property(PropertyBuilder.builder()
                                        .select(HTTP_METHOD)
                                        .title("HTTP Method")
                                        .description("HTTP method used to make the request.")
                                        .required(true)
                                        .defaultValue("GET")
                                        .values(LIST_HTTP_METHOD)
                                        .build())
                .property(PropertyBuilder.builder()
                                        .freeSelect(HTTP_CONTENT_TYPE)
                                        .title("Content Type")
                                        .description("HTTP Content Type.")
                                        .required(true)
                                        .defaultValue("application/json")
                                        .values(LIST_HTTP_CONTENT_TYPE)
                                        .build())
                .property(PropertyBuilder.builder()
                                        .string(HTTP_HEADERS)
                                        .title("Headers")
                                        .description("Add headers in json or yaml format.")
                                        .renderingAsTextarea()
                                        .build())
                .property(PropertyBuilder.builder()
                                        .string(HTTP_BODY)
                                        .title("Body")
                                        .description("Add Body.")
                                        .renderingAsTextarea()
                                        .build())
                .property(PropertyBuilder.builder()
                                        .integer(HTTP_TIMEOUT)
                                        .title("Request Timeout")
                                        .description("How long to wait for a request to complete before failing.")
                                        .defaultValue(DEFAULT_TIMEOUT.toString())
                                        .build())
                .property(PropertyBuilder.builder()
                                        .booleanType(HTTP_NO_SSL_VERIFICATION)
                                        .title("Ignore SSL Verification")
                                        .description("Ignore SSL Verification.")
                                        .defaultValue("false")
                                        .build())
                .property(PropertyBuilder.builder()
                                        .select(HTTP_AUTHENTICATION)
                                        .title("Authentication")
                                        .description("Authentication mechanism to use.")
                                        .required(false)
                                        .defaultValue(AUTH_NONE)
                                        .values(AUTH_NONE, AUTH_BASIC, AUTH_OAUTH2)
                                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Authentication")
                                        .renderingOption(StringRenderingConstants.GROUPING,"secondary")
                                        .build())
                .property(PropertyBuilder.builder()
                                        .string(HTTP_USERNAME)
                                        .title("Username/Client ID")
                                        .description("Username or Client ID to use for authentication.")
                                        .required(false)
                                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Authentication")
                                        .renderingOption(StringRenderingConstants.GROUPING,"secondary")
                                        .build())
                .property(PropertyBuilder.builder()
                                        .string(HTTP_PASSWORD)
                                        .title("Password/Client Secret")
                                        .description("Password or Client Secret to use for authentication.")
                                        .required(false)
                                        .renderingOption(StringRenderingConstants.DISPLAY_TYPE_KEY,
                                        StringRenderingConstants.DisplayType.PASSWORD)
                                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Authentication")
                                        .renderingOption(StringRenderingConstants.GROUPING,"secondary")
                                        .build())
                .property(PropertyBuilder.builder()
                                        .string(HTTP_AUTHTOKEN_ENDPOINT)
                                        .title("OAuth Token URL")
                                        .description("OAuth 2.0 Token Endpoint URL at which to obtain tokens.")
                                        .required(false)
                                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Authentication")
                                        .renderingOption(StringRenderingConstants.GROUPING,"secondary")
                                        .build())
                .property(PropertyBuilder.builder()
                                        .string(HTTP_AUTHTVALIDATE_ENDPOINT)
                                        .title("OAuth Validate URL")
                                        .description("OAuth 2.0 Validate Endpoint URL at which to obtain validate token responses.")
                                        .required(false)
                                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Authentication")
                                        .renderingOption(StringRenderingConstants.GROUPING,"secondary")
                                        .build())
                .property(PropertyBuilder.builder()
                                        .booleanType(HTTP_PROXY_ENABLE)
                                        .title("Use Proxy Settings?")
                                        .description("Set if you want to use a proxy.")
                                        .defaultValue("false")
                                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Proxy Settings")
                                        .renderingOption(StringRenderingConstants.GROUPING,"secondary")
                                        .build())
                .property(PropertyBuilder.builder()
                                        .string(HTTP_PROXY_IP)
                                        .title("Proxy IP")
                                        .description("Proxy to use for this request")
                                        .required(false)
                                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Proxy Settings")
                                        .renderingOption(StringRenderingConstants.GROUPING,"secondary")
                                        .build())
                .property(PropertyBuilder.builder()
                                        .integer(HTTP_PROXY_PORT)
                                        .title("Proxy Port")
                                        .description("Proxy port to use for this request")
                                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Proxy Settings")
                                        .renderingOption(StringRenderingConstants.GROUPING,"secondary")
                                        .required(false)
                                        .build())
                .property(PropertyBuilder.builder()
                                        .booleanType(HTTP_PRINT)
                                        .title("Print Response to File?")
                                        .description("Set if you want to print the response content to a file.")
                                        .defaultValue("false")
                                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Print")
                                        .build())
                .property(PropertyBuilder.builder()
                                        .string(HTTP_PRINT_FILE)
                                        .title("File Path")
                                        .description("File path where you will write the response.")
                                        .required(false)
                                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Print")
                                        .renderingOption(StringRenderingConstants.GROUPING,"secondary")
                                        .build())
                .build();


    @Override
    Description getDescription() {
        return DESCRIPTION
    }

    @Override
    boolean postNotification(String trigger, Map executionData, Map config) {
        String remoteUrl = config.containsKey(HTTP_URL) ? config.get(HTTP_URL).toString() : null
        String method = config.containsKey(HTTP_METHOD) ? config.get(HTTP_METHOD).toString() : null
        String contentTypeStr = config.containsKey(HTTP_CONTENT_TYPE) ? config.get(HTTP_CONTENT_TYPE).toString() : null
        Integer timeout = config.containsKey(HTTP_TIMEOUT) ? Integer.parseInt(config.get(HTTP_TIMEOUT).toString()) : DEFAULT_TIMEOUT
        String headersStr = config.containsKey(HTTP_HEADERS) ? config.get(HTTP_HEADERS).toString() : null
        String bodyStr = config.containsKey(HTTP_BODY) ? config.get(HTTP_BODY).toString() : null
        Boolean ignoreSSL = Boolean.valueOf(config.get(HTTP_NO_SSL_VERIFICATION))
        Boolean proxy = Boolean.valueOf(config.get(HTTP_PROXY_ENABLE))
        Boolean print = Boolean.valueOf(config.get(HTTP_PRINT))
        String printFile = config.containsKey(HTTP_PRINT_FILE) ? config.get(HTTP_PRINT_FILE).toString() : null

        if(remoteUrl == null || method == null) {
            throw new Exception("Remote URL and Method are required.");
        }

        HttpLogger logger = new HttpLogger(log)

        HttpBuilder builder = new HttpBuilder()
        builder.setLog(logger)
        builder.setOauthClients(oauthClients)

        // Setup the request and process it.
        RequestBuilder request = RequestBuilder.create(method)
                .setUri(remoteUrl)
                .setConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(timeout)
                        .setConnectTimeout(timeout)
                        .setSocketTimeout(timeout)
                        .build());

        String authHeader = getAuthentication(config)

        if(authHeader != null) {
            request.setHeader("Authorization", authHeader);
        }

        //add custom headers, it could be json or yml
        if(headersStr !=null){
            builder.setHeaders(headersStr, request);
        }

        if(contentTypeStr){
            request.setHeader("Content-Type", contentTypeStr)
        }

        request.setHeader("trigger", trigger)

        //send body
        if(bodyStr !=null){
            HttpEntity entity = null;
            try {
                entity = new ByteArrayEntity(bodyStr.getBytes("UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            request.setEntity(entity);
        }

        Map<String, Object> configuration = [
                "sslVerify":ignoreSSL,
                "proxySettings": proxy,
                "printResponseToFile": print,
        ]

        if(proxy){
            String proxyIp = config.containsKey(HTTP_PROXY_IP) ? config.get(HTTP_PROXY_IP).toString() : null
            Integer proxyPort = config.containsKey(HTTP_PROXY_PORT) ? Integer.parseInt(config.get(HTTP_PROXY_PORT).toString()) : null
            configuration.put("proxyIP", proxyIp)
            configuration.put("proxyPort", proxyPort)
        }

        if(print){
            configuration.put("file", printFile)
        }

        try {
            builder.doRequest(configuration, request.build(), 1)
        } catch (StepException e) {
            log.error(e.getMessage())
            return false
        }

        return true

    }

    def getAuthentication(Map config){

        String authentication = config.containsKey(HTTP_AUTHENTICATION) ? config.get(HTTP_AUTHENTICATION).toString() : AUTH_NONE
        String password = config.containsKey(HTTP_PASSWORD) ? config.get(HTTP_PASSWORD).toString() : AUTH_NONE

        String authHeader = null

        if(authentication.equals(AUTH_BASIC)) {
            String username = config.containsKey(HTTP_USERNAME) ? config.get(HTTP_USERNAME).toString() : AUTH_NONE

            if(username == null || password == null) {
                throw new Exception("Username and password not provided for BASIC Authentication");
            }

            authHeader = username + ":" + password;

            //As per RFC2617 the Basic Authentication standard has to send the credentials Base64 encoded.
            authHeader = "Basic " + com.dtolabs.rundeck.core.utils.Base64.encode(authHeader);
        } else if (authentication.equals(AUTH_OAUTH2)) {
            // Get an OAuth token and setup the auth header for OAuth
            String tokenEndpoint = config.containsKey(HTTP_AUTHTOKEN_ENDPOINT) ? config.get(HTTP_AUTHTOKEN_ENDPOINT).toString() : null;
            String validateEndpoint = config.containsKey(HTTP_AUTHTVALIDATE_ENDPOINT) ? config.get(HTTP_AUTHTVALIDATE_ENDPOINT).toString() : null;
            String clientId = config.containsKey(HTTP_USERNAME) ? config.get(HTTP_USERNAME).toString() : null;
            String clientSecret = password;

            if(tokenEndpoint == null) {
                throw new Exception("Token endpoint not provided for OAuth 2.0 Authentication.");
            }

            String clientKey = clientId + "@" + tokenEndpoint;
            String accessToken;

            // Another thread may be trying to do the same thing.
            synchronized(this.oauthClients) {
                OAuthClient client;

                if(this.oauthClients.containsKey(clientKey)) {
                    // Update the existing client with our options if it exists.
                    // We do this so that changes to configuration will always
                    // update clients on next run.
                    log.trace("Found existing OAuth client with key " + clientKey);
                    client = this.oauthClients.get(clientKey);
                    client.setCredentials(clientId, clientSecret);
                    client.setValidateEndpoint(validateEndpoint);
                } else {
                    // Create a brand new client
                    log.trace("Creating new OAuth client with key " + clientKey);
                    client = new OAuthClient(OAuthClient.GrantType.CLIENT_CREDENTIALS);
                    client.setCredentials(clientId, clientSecret);
                    client.setTokenEndpoint(tokenEndpoint);
                    client.setValidateEndpoint(validateEndpoint);
                }

                // Grab the access token
                try {
                    log.trace("Attempting to fetch access token...");
                    accessToken = client.getAccessToken();
                } catch(Exception ex) {
                    Exception se = new Exception("Error obtaining OAuth Access Token: " + ex.getMessage());
                    se.initCause(ex);
                    throw se;
                }

                this.oauthClients.put(clientKey, client);
            }

            authHeader = "Bearer " + accessToken;
        }
        return authHeader

    }

}
