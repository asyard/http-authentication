package com.asy.http.server.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * From spring-spring-security-web
 *
 * https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/authentication/www
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



    // from : org.springframework.security.web.authentication.www.DigestAuthUtils.splitEachArrayElementAndCreateMap
    public static Map<String, String> splitEachArrayElementAndCreateMap(String[] array, String delimiter, String removeCharacters) {
        if ((array == null) || (array.length == 0)) {
            return null;
        }

        Map<String, String> map = new HashMap<String, String>();

        for (String s : array) {
            String postRemove;

            if (removeCharacters == null) {
                postRemove = s;
            } else {
                postRemove = StringUtils.replace(s, removeCharacters, "");
            }

            String[] splitThisArrayElement = split(postRemove, delimiter);

            if (splitThisArrayElement == null) {
                continue;
            }

            map.put(splitThisArrayElement[0].trim(), splitThisArrayElement[1].trim());
        }

        return map;
    }

    private static String[] split(String toSplit, String delimiter) {
        if (delimiter.length() != 1) {
            throw new IllegalArgumentException("Delimiter can only be one character in length");
        }

        int offset = toSplit.indexOf(delimiter);

        if (offset < 0) {
            return null;
        }

        String beforeDelimiter = toSplit.substring(0, offset);
        String afterDelimiter = toSplit.substring(offset + 1);

        return new String[]{beforeDelimiter, afterDelimiter};
    }

    private static final String[] EMPTY_STRING_ARRAY = new String[0];

    public static String[] splitIgnoringQuotes(String str, char separatorChar) {
        if (str == null) {
            return null;
        }

        int len = str.length();

        if (len == 0) {
            return EMPTY_STRING_ARRAY;
        }

        List<String> list = new ArrayList<String>();
        int i = 0;
        int start = 0;
        boolean match = false;

        while (i < len) {
            if (str.charAt(i) == '"') {
                i++;
                while (i < len) {
                    if (str.charAt(i) == '"') {
                        i++;
                        break;
                    }
                    i++;
                }
                match = true;
                continue;
            }
            if (str.charAt(i) == separatorChar) {
                if (match) {
                    list.add(str.substring(start, i));
                    match = false;
                }
                start = ++i;
                continue;
            }
            match = true;
            i++;
        }
        if (match) {
            list.add(str.substring(start, i));
        }

        return list.toArray(new String[list.size()]);
    }


}
