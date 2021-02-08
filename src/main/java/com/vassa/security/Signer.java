package com.vassa.security;

import com.vassa.domain.Algorithm;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public class Signer {

    private final Sign sign;
    private final SignatureAuth signatureAuth;
    private final Algorithm algorithm;

    private static final Charset CHARSET_UTF8 = StandardCharsets.UTF_8;

    public Signer(final Key key, final SignatureAuth signatureAuth) {
        requireNonNull(key, "Key cannot be null");
        this.signatureAuth = requireNonNull(signatureAuth, "Signature cannot be null");
        final String algorithmName = signatureAuth.getAlgorithm();
        this.algorithm = Algorithm.get(algorithmName);

        if (java.security.Signature.class.equals(algorithm.getType())) {
            this.sign = new Asymmetric(PrivateKey.class.cast(key));
        } else if (Mac.class.equals(algorithm.getType())) {
            this.sign = new Symmetric(key);
        } else {
            throw new RuntimeException("Unsupported Algorithm type: " + algorithm.getType());
        }

        try {
            sign.sign("validation".getBytes());
        } catch (final RuntimeException e) {
            throw (RuntimeException) e;
        } catch (final Exception e) {
            throw new IllegalStateException("Can't initialise the Signer using the provided algorithm and key", e);
        }
    }

    public SignatureAuth sign(final String method, final String uri, final Map<String, String> headers) throws IOException {
        final String signingString = createSigningString(method, uri, headers);

        final byte[] binarySignature = sign.sign(signingString.getBytes(CHARSET_UTF8));

        final byte[] encoded = Base64.encodeBase64(binarySignature);

        final String signedAndEncodedString = new String(encoded, CHARSET_UTF8);

        return new SignatureAuth(signatureAuth.getKeyId(),
                algorithm.getPortableName(),
                signedAndEncodedString, signatureAuth.getHeaders());
    }

    public String createSigningString(final String method, final String uri, final Map<String, String> headers) throws IOException {
        return Signatures.createSigningString(signatureAuth.getHeaders(), method, uri, headers);
    }

    private interface Sign {
        byte[] sign(byte[] signingStringBytes);
    }

    private class Asymmetric implements Sign {

        private final PrivateKey key;

        public Asymmetric(final PrivateKey key) {
            this.key = key;
        }

        @Override
        public byte[] sign(final byte[] signingStringBytes) {
            try {
                final Signature instance = Signature.getInstance(algorithm.getJvmName());
                instance.initSign(key);
                instance.update(signingStringBytes);
                return instance.sign();
            } catch (final NoSuchAlgorithmException e) {
                throw new RuntimeException("Unsupported algorithm: " + algorithm);
            } catch (final Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private class Symmetric implements Sign {

        private final Key key;

        private Symmetric(final Key key) {
            this.key = key;
        }

        @Override
        public byte[] sign(final byte[] signingStringBytes) {
            try {
                final Mac mac = Mac.getInstance(algorithm.getJvmName());
                mac.init(key);
                return mac.doFinal(signingStringBytes);
            } catch (final NoSuchAlgorithmException e) {
                throw new RuntimeException("Unsupported algorithm: " + algorithm);
            } catch (final Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

}
