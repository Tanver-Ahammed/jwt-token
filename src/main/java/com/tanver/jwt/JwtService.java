package com.tanver.jwt;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;

@Service
public class JwtService {

    private final KeyUtil keyUtil;

    public JwtService(KeyUtil keyUtil) {
        this.keyUtil = keyUtil;
    }

    public String generateJwt(String subject) throws Exception {
        String headerJson = "{\"alg\":\"RS256\",\"type\":\"JWT\"}";
        String payloadJson = String.format("{\"sub\":\"%s\",\"exp\":%d}", subject, (System.currentTimeMillis() / 1000) + 600);

        String header = base64UrlEncode(headerJson);
        String payload = base64UrlEncode(payloadJson);

        String data = header + "." + payload;

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyUtil.getPrivateKey());
        signer.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signer.sign();
        String signature = base64UrlEncode(signatureBytes);

        return data + "." + signature;
    }

    public boolean validateJwt(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) return false;

        String header = parts[0];
        String payload = parts[1];
        String signature = parts[2];

        String data = header + "." + payload;
        byte[] signatureBytes = Base64.getUrlDecoder().decode(signature);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        String publicKey = String.valueOf(keyUtil.getPublicKey());
        System.out.println(publicKey);
        verifier.initVerify(keyUtil.getPublicKey());
        verifier.update(data.getBytes(StandardCharsets.UTF_8));

        boolean signatureValid = verifier.verify(signatureBytes);
        if (!signatureValid) return false;

        String payloadJson = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
        long exp = extractExpFromJson(payloadJson);
        return exp > System.currentTimeMillis() / 1000;
    }

    private long extractExpFromJson(String payloadJson) {
        int start = payloadJson.indexOf("\"exp\":") + 6;
        int end = payloadJson.indexOf(",", start);
        if (end == -1) end = payloadJson.indexOf("}", start);
        return Long.parseLong(payloadJson.substring(start, end).trim());
    }

    private String base64UrlEncode(String input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    private String base64UrlEncode(byte[] input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }
}

//eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0YW52ZXItQWhhbW1lZCIsImV4cCI6MTc0Nzg5NDE4MH0.WHr8NwJ-YsDzTR-IT2eRmkm3wKhXrv2SN3qV2gbqJbbChegFrtoJABmNBxeIp3AHPtmk7-rtExaw1mE_sqtSrCpT1T6TsQ-pqLeWdvXOfUUZ0rlrpJsH498HVax96DhzvsFE-selBFUt1qooipvvNoYHIxHq6auVMVlmcdKl4dNYFCATG2r9SVRogbCbB-z7E1Zn_nFYSLWm1_i9vt13M2RMx84QTtryy6x2QYFSySmpUrluvFmIwsIzdSzfQk97CUB6c8NjFWIs85mtignwqRd2KN8nsQXVRakx6GjL30W5XSDEMjySGWhFpHJnclsepiOKH0WSR1tfVoA8MrlA-g
//eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0YW52ZXItQWhhbW1lZCIsImV4cCI6MTc0Nzg5NDE4MX0.F5rRjaRX88YbTasAZG6Dvjk0qd7V4WPfFvJFFyxqXYuTDXIh1twjCdI8B659WpUlORfehPwiAWKW5VI66V2586saaVHullXuugK2JFUn95SPCmuu3VYoqZghVfzy_e0WSmNl2pwEuTdPg4JjZQ_DTKDUWeNrFzyA7k3oPms2c4qOzfRKtHI1HKjUc_ooxW2zBri1bBTuWAOGvKoYI0Vl975aSlnZS0eEmUFWRVSJZqBD5aqsYX2JuvdnCnVtU_dTf3YHFZEedUkHipZUTozwtmcrZGz4uPilskAs-NnnBLmYfZC1pYNbaC9Sz_R9iTrK5f8sscQJ-YjkQ4d-DRM65w
//eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0YW52ZXItQWhhbW1lZCIsImV4cCI6MTc0Nzg5NDE5NX0.YibxNlh1302ql4MKLgtU0FvIlu2tR6XAnHRNwSNIKzIaOeBQ3u_zBprjo9kcQcgKKUjyJP85dCp9lHV7EcHlSu3fW61i3N5TySdyoNFoc2_rHh4haI2sfMDZiooDQyxpcbZMfKHQo-7yDWut_J-v1IHQQaTpPANvb8ZRU0N7NsVTtNPL-h3bdtOYtvUSfNt4oEjwtPQ88GmpF6miJ7PRGfrtxqRrEHK97hwiO3NjKYYmj-0pgb_dBRccPZy9Mzxq34m6iscWvYVYmPENVDXY333kaxERNDjIh8lzqWbemJUCZd7V8juSduUkJvXgY435bgYIgcwbLi-3Uus98QCprA
