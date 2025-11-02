package com.portfolio.config;

import com.autopilot.config.exception.ApplicationException;
import com.autopilot.config.exception.ApplicationExceptionTypes;
import com.autopilot.config.logging.AppLogger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class KeyConfig {

    AppLogger log = new AppLogger(LoggerFactory.getLogger(KeyConfig.class));

    @Value("${jwt.keystore.path}")
    private String keyStorePath;

    @Value("${jwt.keystore.password}")
    private String keyStorePassword;

    @Value("${jwt.keystore.key-alias}")
    private String keyAlias;

    /**
     * Loads the private key from the keystore.
     */
    @Bean
    public RSAPrivateKey jwtPrivateKey() {
        try {
            KeyStore keyStore = loadKeyStore();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyStorePassword.toCharArray());
            if (privateKey == null) {
                throw new ApplicationException(ApplicationExceptionTypes.KEY_LOAD_ERROR, "Private key not found in keystore with alias: " + keyAlias);
            }
            log.info("Private key loaded successfully from keystore with alias: " + keyAlias);
            return (RSAPrivateKey) privateKey;
        } catch (ApplicationException e) {
            throw e; // already wrapped
        } catch (Exception e) {
            throw new ApplicationException(ApplicationExceptionTypes.KEY_LOAD_ERROR);
        }
    }

    /**
     * Loads the public key from the keystore certificate.
     */
    @Bean
    public RSAPublicKey jwtPublicKey() {
        try {
            KeyStore keyStore = loadKeyStore();
            Certificate cert = keyStore.getCertificate(keyAlias);
            if (cert == null) {
                throw new ApplicationException(ApplicationExceptionTypes.KEY_LOAD_ERROR, "Certificate not found in keystore with alias: " + keyAlias);
            }
            PublicKey publicKey = cert.getPublicKey();
            log.info("Public key loaded successfully from keystore with alias: " + keyAlias);
            return (RSAPublicKey) publicKey;
        } catch (ApplicationException e) {
            throw e;
        } catch (Exception e) {
            throw new ApplicationException(ApplicationExceptionTypes.KEY_LOAD_ERROR);
        }
    }

    /**
     * Loads the keystore from the classpath.
     */
    private KeyStore loadKeyStore() {
        try (InputStream is = getClass().getResourceAsStream("/keys/jwt-keystore.p12")) {
            if (is == null) {
                throw new ApplicationException(ApplicationExceptionTypes.KEY_LOAD_ERROR, "Keystore file not found at path: /keys/jwt-keystore.p12"
                );
            }
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(is, keyStorePassword.toCharArray());
            return keyStore;
        } catch (ApplicationException e) {
            throw e;
        } catch (Exception e) {
            throw new ApplicationException(ApplicationExceptionTypes.KEY_LOAD_ERROR);
        }
    }
}
