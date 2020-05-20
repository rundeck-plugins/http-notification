package com.rundeck.plugin.oauth

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import groovyx.net.http.HTTPBuilder
import groovyx.net.http.HttpResponseException
import groovyx.net.http.Method
import org.apache.http.util.EntityUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Created by rundeck on 12/27/17.
 */
class OAuthClient {
    private static final Logger log = LoggerFactory.getLogger(OAuthClient.class);


    public static final String JSON_CONTENT_TYPE = "application/json";
    public static final String FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";

    public static final String FIELD_GRANT_TYPE = "grant_type";
    public static final String FIELD_ACCESS_TOKEN = "access_token";


    public static final Integer STATUS_SUCCESS = 200;
    public static final Integer STATUS_AUTHORIZATION_REQUIRED = 401;

    protected ObjectMapper jsonParser = new ObjectMapper();

    enum GrantType {
        CLIENT_CREDENTIALS
    }

    static class OAuthException extends Exception {
        OAuthException(String message) {
            super(message);
        }
    }


    String clientId;
    String clientSecret;
    GrantType grantType;
    String tokenEndpoint;
    String validateEndpoint;
    String accessToken;


    void doTokenRequest() throws  OAuthException, IOException {
        this.accessToken = null;

        def requestHeaders = [:]
        requestHeaders."Authorization" = "Basic " + com.dtolabs.rundeck.core.utils.Base64.encode(this.clientId + ":" + this.clientSecret)
        requestHeaders."Accept" = JSON_CONTENT_TYPE
        requestHeaders."Content-Type" = FORM_CONTENT_TYPE

        def http = new HTTPBuilder(this.tokenEndpoint)

        this.accessToken = http.request(Method.POST, FORM_CONTENT_TYPE) { req ->

            // add possible headers
            requestHeaders.each { key, value ->
                headers."${key}" = "${value}"
            }

            body = ["${this.FIELD_GRANT_TYPE}": this.grantType.name().toLowerCase()]

            response.success = { resp, json ->
                JsonNode data = jsonParser.readTree(EntityUtils.toString(json));
                String token = data.get(FIELD_ACCESS_TOKEN).asText();
                return token
            }

            response.failure = { resp ->
                "Unexpected failure: ${resp.statusLine}"
                return null
            }

            response.'404' = {
                println 'Not found'
                return null
            }
        }

        if(this.accessToken == null) {
            throw new Exception("Error getting the token");
        }

        this.doTokenValidate(true);
    }


    void doTokenValidate() throws HttpResponseException, IOException, OAuthException {
        this.doTokenValidate(false);
    }


    void doTokenValidate(Boolean newToken) throws HttpResponseException, IOException, OAuthException {
        if(this.accessToken == null) {
            this.doTokenRequest();
        }

        if(this.validateEndpoint != null) {
            def http = new HTTPBuilder(this.tokenEndpoint)

            def requestHeaders = [:]
            requestHeaders."Authorization" = "Bearer " + this.accessToken
            requestHeaders."Accept" = JSON_CONTENT_TYPE

            String clientId = http.request(Method.GET,JSON_CONTENT_TYPE) { req ->

                // add possible headers
                requestHeaders.each { key, value ->
                    println "${key} - ${value}"
                    headers."${key}" = "${value}"
                }

                body = ["${this.FIELD_GRANT_TYPE}": this.grantType.name().toLowerCase()]

                response.success = { resp, json ->

                    if(resp.statusLine==STATUS_SUCCESS){
                        String clientId = json.client
                        return clientId
                    }else if (resp.statusLine == STATUS_AUTHORIZATION_REQUIRED) {
                        return "newAuth"
                    }else {
                        return null
                    }
                }

                response.failure = { resp ->
                    println "Unexpected failure: ${resp.statusLine}"
                    return null
                }

                response.'404' = {
                    println 'Not found'
                    return null
                }
            }

            if(clientId==null){
                throw new OAuthException("It couldn't get the node");
            }

            if(clientId.equals("newAuth")){
                this.accessToken = null;
                if(newToken) {
                    throw new OAuthException("Newly acquired token is still not valid.");
                } else {
                    doTokenRequest();
                }
            }else{
                if (!this.clientId.equals(clientId)) {
                    throw new OAuthException("Token received for a client other than us.");
                }
            }

        } else {
            log.debug("No validate endpoint exists, skipping validation.");
        }
    }

    OAuthClient(GrantType grantType) {
        this.grantType = grantType;
    }


    void setCredentials(String clientId, String clientSecret) {
        log.trace("Setting credentials to " + this.clientId + ":" + this.clientSecret);

        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    void setValidateEndpoint(String validateEndpoint) {
        this.validateEndpoint = validateEndpoint;
    }


    String getAccessToken() throws OAuthException, Exception {
        if(this.accessToken == null) {
            this.doTokenValidate();
        }

        return this.accessToken;
    }

}

