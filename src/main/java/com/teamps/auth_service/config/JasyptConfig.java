//package com.teamps.auth_service.config;
//
//import org.jasypt.encryption.StringEncryptor;
//import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
//import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
//import org.jasypt.salt.RandomSaltGenerator;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class JasyptConfig {
//
//    @Value("${jasypt.encryptor.password}")
//    private String password;
//
//    @Bean("jasyptStringEncryptor")
//    public StringEncryptor stringEncryptor() {
//        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
//        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
//        config.setPassword(password);
//        config.setAlgorithm("PBEWithHMACSHA512AndAES_256");
//        config.setKeyObtentionIterations("10000");
//        config.setPoolSize("1");
//        config.setProviderName("SunJCE");
//        config.setSaltGenerator(new RandomSaltGenerator());
//        config.setSaltGeneratorClassName("org.jasypt.iv.RandomIvGenerator");
//        config.setStringOutputType("base64");
//        encryptor.setConfig(config);
//        return encryptor;
//    }
//}
