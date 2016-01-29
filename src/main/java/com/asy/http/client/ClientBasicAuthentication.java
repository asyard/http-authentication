package com.asy.http.client;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.logging.Logger;

/**
 * Created by asy
 */
public class ClientBasicAuthentication {

    private static final Logger logger = Logger.getLogger(ClientBasicAuthentication.class.getName());

    public static void main(String[] args) throws IOException {

        String userName = "user1", userPassword = "pass1";

        String encoding = new String(Base64.encodeBase64((userName + ":" + userPassword).getBytes()));
        HttpPost httppost = new HttpPost("http://localhost:8070/");
        httppost.setHeader("Authorization", "Basic " + encoding);

        DefaultHttpClient httpclient = new DefaultHttpClient();
        logger.info("executing request " + httppost.getRequestLine());
        HttpResponse response = httpclient.execute(httppost);
        HttpEntity entity = response.getEntity();

        String theString = convertStreamToString(entity.getContent());  //org.apache.commons.io.IOUtils.toString(entity.getContent(), "UTF-8");
        logger.info("Response : " + theString);

        EntityUtils.consume(entity);
    }

    static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

}
