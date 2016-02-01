package com.asy.http.server.filter;

import com.asy.http.server.ServerTest;
import com.asy.http.server.utils.DigestUtils;
import com.asy.http.server.utils.StringUtils;
import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.HttpExchange;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpStatus;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Created by asy
 */
public class AuthenticationControlFilter extends Filter {

    private static final Logger logger = Logger.getLogger(AuthenticationControlFilter.class.getName());

    @Override
    public void doFilter(HttpExchange httpExchange, Chain chain) throws IOException {
        logger.info("Checking request");

        if (httpExchange.getRequestHeaders().getFirst("Authorization") != null) {
            String authorizationHeader = httpExchange.getRequestHeaders().getFirst("Authorization");

            try {
                if (authorizationHeader.startsWith("Basic")) {
                    checkBasicAuthentication(authorizationHeader);
                } else if (authorizationHeader.startsWith("Digest")) {
                    checkDigestAuthentication(authorizationHeader, httpExchange.getRequestMethod());
                } else {
                    sendMessage(httpExchange, HttpStatus.SC_BAD_REQUEST, "Unrecognized authorization header. ");
                    return;
                }
            } catch (Exception e) {
                sendMessage(httpExchange, HttpStatus.SC_UNPROCESSABLE_ENTITY, "Request control failed. " + e.getMessage());
                return;
            }
            logger.info("Request controlled");
            chain.doFilter(httpExchange);
            return;
        }

        // send WWW-Authenticate to client
        logger.warning("Request header is empty. Sending WWW-Authenticate Digest message");
        try {
            sendWWWAuthenticateDigestMessage(httpExchange);
        } catch (NoSuchAlgorithmException e) {
            sendMessage(httpExchange, HttpStatus.SC_INTERNAL_SERVER_ERROR, "Request challenge could not be sent");
        }
        return;
    }

    private void sendMessage(HttpExchange httpExchange, int code, String message) throws IOException {
        httpExchange.sendResponseHeaders(code, message.length());
        OutputStream os = httpExchange.getResponseBody();
        os.write(message.getBytes());
        os.close();
    }

    private void sendWWWAuthenticateDigestMessage(HttpExchange httpExchange) throws NoSuchAlgorithmException, IOException {
        long expiryTime = System.currentTimeMillis() + (ServerTest.NONCE_VALIDITY_SECONDS * 1000);
        String signatureValue = DigestUtils.getMD5Digest(expiryTime + ":" + ServerTest.NONCE_KEY);
        String nonceValue = expiryTime + ":" + signatureValue;
        String nonceValueBase64 = new String(Base64.encodeBase64(nonceValue.getBytes()));

        String authenticationHeader = "Digest realm=\"" + ServerTest.SERVER_REALM + "\", " + "qop=\"auth\", nonce=\"" + nonceValueBase64 + "\"";
        httpExchange.getResponseHeaders().set("WWW-Authenticate", authenticationHeader);
        sendMessage(httpExchange, HttpStatus.SC_UNAUTHORIZED, authenticationHeader);
    }

    private void checkBasicAuthentication(String authorizationHeader) throws Exception {
        String digestData = authorizationHeader.split("\\s+")[1];
        String[] decodedUserInfo = new String(Base64.decodeBase64(digestData.getBytes())).split(":");

        if (!ServerTest.allowedUsers.containsKey(decodedUserInfo[0])) {
            throw new Exception("User not found");
        }

        if (!ServerTest.allowedUsers.get(decodedUserInfo[0]).equals(decodedUserInfo[1])) {
            throw new Exception("Authorization failed");
        }
    }

    private void checkDigestAuthentication(String authorizationHeader, String requestMethod) throws Exception {
        Map<String, String> headerMap = parseDigestAuthorizationHeader(authorizationHeader);
        String username = headerMap.get("username");
        String realm = headerMap.get("realm");
        String nonce = headerMap.get("nonce");
        String uri = headerMap.get("uri");
        String response = headerMap.get("response");
        String qop = headerMap.get("qop");
        String nc = headerMap.get("nc");
        String cnonce = headerMap.get("cnonce");

        // Check all required parameters were supplied (ie RFC 2069)
        if (username == null || realm == null || nonce == null || uri == null || response == null) {
            throw new Exception("Missing mandatory digest value");
        }

        // Check all required parameters for an "auth" qop were supplied (ie RFC 2617)
        if ("auth".equals(qop)) {
            if (nc == null || cnonce == null) {
                throw new Exception("Header has missing value(s) based on qop");
            }
        }

        // Check realm name equals what we expected
        if (!ServerTest.SERVER_REALM.equals(realm)) {
            throw new Exception("Response realm is incorrect");
        }

        // Check nonce was Base64 encoded
        if (!Base64.isBase64(nonce.getBytes())) {
            throw new Exception("Received nonce is not encoded in Base64");
        }

        // Decode nonce from Base64
        // Format of nonce is:
        // base64(expirationTime + ":" + md5Hex(expirationTime + ":" + noncekey))
        String nonceAsPlainText = new String(Base64.decodeBase64(nonce.getBytes()));
        String[] nonceTokens = StringUtils.delimitedListToStringArray(nonceAsPlainText, ":");

        if (nonceTokens.length != 2) {
            throw new Exception("Nonce should have yielded 2 tokens but was " + nonceTokens.length);
        }

        // Extract expiry time from nonce
        long nonceExpiryTime = -1L;
        try {
            nonceExpiryTime = new Long(nonceTokens[0]).longValue();
        } catch (NumberFormatException e) {
            throw new Exception("Nonce should have yielded a numeric first token");
        }

        if (nonceExpiryTime < System.currentTimeMillis()) {
            throw new Exception("Nonce expired");
        }

        // Check signature of nonce matches this expiry time
        String expectedNonceSignature = DigestUtils.getMD5Digest(nonceExpiryTime + ":" + ServerTest.NONCE_KEY);

        if (!expectedNonceSignature.equals(nonceTokens[1])) {
            throw new Exception("Nonce token compromised");
        }


        if (!ServerTest.allowedUsers.containsKey(username)) {
            throw new Exception("User not found");
        }


        String serverDigestMd5 = DigestUtils.generateDigest(username, ServerTest.allowedUsers.get(username), realm, requestMethod, uri, qop, nonce, nc, cnonce);
        if (!serverDigestMd5.equals(response)) {
            throw new Exception("Response check failed. Check your login information");
        }

    }

    // for a better way, from spring-security-web : DigestAuthUtils class can be used.
    private Map<String, String> parseDigestAuthorizationHeader(String authorizationHeader) {
        String seciton212response = authorizationHeader.substring(7);
        String[] headerEntries = DigestUtils.splitIgnoringQuotes(seciton212response, ',');
        return DigestUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");
    }


    @Override
    public String description() {
        return "authenticationControlFilterDescription";
    }

}
