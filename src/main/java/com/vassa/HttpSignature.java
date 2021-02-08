package com.vassa;

import com.vassa.client.ApiClient;
import com.vassa.client.HttpMethod;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class HttpSignature {

    public static void main(String[] args) throws IOException {
        long t = System.currentTimeMillis();
        System.out.println("\nStart script\n");
        if(args.length == 0) {
            System.err.println("Cannot pass parameter...");
            System.exit(1);
        }

        String method = args[0];
        HttpMethod httpMethod = getHttpMethod(method);
        validateInputParamByHttpMethod(httpMethod, args);
        ApiClient apiClient = null;
        try {
            apiClient = new ApiClient(args[1], args[2], args[3]);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("Exception on create ApiClient: " + e);
            System.exit(2);
        }
        switch(httpMethod) {
            case GET:
                apiClient.getMethod();
                break;
            case POST:
                apiClient.postMethod(args[4]);
                break;
            case PUT:
                apiClient.putMethod(args[4]);
                break;
            case DELETE:
                apiClient.deleteMethod();
                break;
            default:
                throw new IllegalArgumentException("This argument is not valid: " + httpMethod);
        }
        System.out.println(String.format("\nEnd script in %s ms", System.currentTimeMillis() - t));
    }

    private static void validateInputParamByHttpMethod(HttpMethod method, String[] args) {
        int length = args.length;
        switch(method) {
            case POST:
            case PUT:
                if(length < 5) {
                    throw new IllegalArgumentException("Missing any paramters for http " + method + ".");
                }
                break;
            case GET:
            case DELETE:
                if(length < 4) {
                    throw new IllegalArgumentException("Missing any paramters for http " + method + ".");
                }
                break;
            default:
                throw new IllegalArgumentException("Not supported method: "+ method);
        }
    }

    private static HttpMethod getHttpMethod(final String method) {
        if(method == null || method.trim().equals("")) {
            throw new IllegalArgumentException("Method is not set");
        }
        try {
            return HttpMethod.valueOf(method.toUpperCase());
        } catch(Exception e) {
            throw new IllegalArgumentException("Http method doesn't valid: " + method);
        }
    }

}
