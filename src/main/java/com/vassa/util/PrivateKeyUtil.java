package com.vassa.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class PrivateKeyUtil {

    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    private static final String EMPTY_STR = "";
    private static final String KEYFACTORY_INSTANCE = "RSA";


    public static PrivateKey loadPrivateKey(final String pathFile) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        if(pathFile == null || EMPTY_STR.equals(pathFile.trim())) {
            throw new IllegalArgumentException("Path file is not valid: [" + pathFile + "].");
        }
        return readPrivateKey(pathFile);
    }

    private static PrivateKey readPrivateKey(String pathFile)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String key = readFileAsString(pathFile);
        String privateKeyPEM = getOnlyKeyValue(key);
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance(KEYFACTORY_INSTANCE);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }

    private static String getOnlyKeyValue(String key) {
        return key.replace(BEGIN_PRIVATE_KEY, EMPTY_STR)
                .replaceAll(System.lineSeparator(), EMPTY_STR)
                .replace(END_PRIVATE_KEY, EMPTY_STR);
    }

    private static String readFileAsString(final String pathFile) throws IOException {
        Path path = Paths.get(pathFile);
        byte[] keyBytes = Files.readAllBytes(path);
        return new String(keyBytes, StandardCharsets.UTF_8);
    }
}
