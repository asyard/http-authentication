package com.asy.http.server;

import com.asy.http.server.core.BasicHttpServer;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by asy
 */
public class ServerTest {

    // Sample users
    public static Map<String, String> allowedUsers;

    // For Digest Authentication
    public static String SERVER_REALM = "serverrealm";
    public static String NONCE_KEY= "servernoncekey";
    public static int NONCE_VALIDITY_SECONDS = 30;

    public static void main(String[] args) throws IOException {
        allowedUsers = new HashMap<String, String>();
        allowedUsers.put("user1", "pass1");
        allowedUsers.put("user2", "pass2");
        allowedUsers.put("user3", "pass3");
        allowedUsers.put("user4", "pass4");
        allowedUsers.put("user5", "pass5");

        new BasicHttpServer(8070, "");
    }
}
