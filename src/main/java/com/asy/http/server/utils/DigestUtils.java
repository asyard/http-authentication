package com.asy.http.server.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * From spring-spring-security-web
 *
 * https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/authentication/www/DigestAuthenticationEntryPoint.java
 *
 */
public class DigestUtils {

    public static String getMD5Digest(String value) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return new String(HexUtils.encode(digest.digest(value.getBytes())));
    }

    public static String generateDigest(String username, String password, String realm, String httpMethod,
                                        String uri, String qop, String nonce, String nc, String cnonce) {

        try {
            String a1 = username + ":" + realm + ":" + password;
            String a1Md5 = getMD5Digest(a1);

            String a2 = httpMethod + ":" + uri;
            String a2Md5 = getMD5Digest(a2);

            String digest = "";
            if (qop == null) {
                // as per RFC 2069 compliant clients (also referred by RFC 2617)
                digest = a1Md5 + ":" + nonce + ":" + a2Md5;
            } else if ("auth".equals(qop)) {
                 // as per RFC 2617 compliant clients
                digest = a1Md5 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + a2Md5;
            } else {
                throw new Exception("This method does not support this qop : " + qop);
            }

            return getMD5Digest(digest);

        } catch (Exception e) {
            System.out.println("Digest error. Returning null");
            e.printStackTrace();
            return null;
        }
    }


}
