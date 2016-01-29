package com.asy.http.client;

import org.apache.http.*;
import org.apache.http.auth.AUTH;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by asy
 *
 * Original code from :
 * http://bethecoder.com/applications/tutorials/tools-and-libs/commons-http-client/digest-authentication.html
 *
 *
 */
public class ClientDigestAuthentication {

    private static final Logger logger = Logger.getLogger(ClientDigestAuthentication.class.getName());

    public static void main(String[] args) throws IOException {
        String host = "127.0.0.1";
        int port = 8070;
        String protocol = "http";
        String username = "user2";
        String password = "pass2";
        String requestContent = "hello from client";

        CloseableHttpClient closeableHttpClient = HttpClientBuilder.create().build();

        HttpHost targetHost = new HttpHost(host, port, protocol);

        HttpPost httpPostRequest = new HttpPost("/");
        //httpPostRequest.addHeader("Context-Type", "application/timestamp-query");

        HttpResponse httpResponse = null;
        try {
            // step 1 : initial request without credentials. Should return HTTP 1.1 401 Unauthorized
            CloseableHttpResponse closeableHttpResponse = closeableHttpClient.execute(targetHost, httpPostRequest);
            logger.info("Step1 Response Code : " + closeableHttpResponse.getStatusLine().getStatusCode());

            if (closeableHttpResponse.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                Header authHeader = closeableHttpResponse.getFirstHeader(AUTH.WWW_AUTH);

                // step 2 : prepare actual request
                DigestScheme digestAuth = new DigestScheme();
                digestAuth.processChallenge(authHeader);

                UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials(username, password);
                httpPostRequest.addHeader(digestAuth.authenticate(usernamePasswordCredentials, httpPostRequest));
                HttpEntity httpEntity = new ByteArrayEntity(requestContent.getBytes());
                httpPostRequest.setEntity(httpEntity);

                // step 3 : send actual request
                HttpClient httpClient = new DefaultHttpClient();
                httpResponse = httpClient.execute(targetHost, httpPostRequest);
                String theString = convertStreamToString(httpResponse.getEntity().getContent());  //org.apache.commons.io.IOUtils.toString(entity.getContent(), "UTF-8");
                logger.info("Response : " + httpResponse.getStatusLine().getStatusCode() + " - " + theString);
            } else {
                //TODO
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Request failed ", e);
        } finally {
            EntityUtils.consume(httpResponse.getEntity());
        }

    }


    static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }


}
