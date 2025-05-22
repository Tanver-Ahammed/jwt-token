package com.tanver.jwt;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/jwt")
public class JwtController {

    private final JwtService jwtService;
    private final KeyUtil keyUtil;

    public JwtController(JwtService jwtService, KeyUtil keyUtil) {
        this.jwtService = jwtService;
        this.keyUtil = keyUtil;
    }

    @GetMapping("/generate")
    public ResponseEntity<String> generate(@RequestParam(defaultValue = "tanver") String subject) throws Exception {
        String token = jwtService.generateJwt(subject);
        return ResponseEntity.ok(token);
    }

    @PostMapping("/validate")
    public ResponseEntity<String> validate(@RequestBody String token) {
        try {
            boolean valid = jwtService.validateJwt(token);
            return ResponseEntity.ok(valid ? "✅ Valid JWT" : "❌ Invalid or Expired JWT");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("❌ Error: " + e.getMessage());
        }
    }

    @GetMapping("/public-key")
    public ResponseEntity<String> getPublicKey() {
        return ResponseEntity.ok(keyUtil.getPublicKeyPEM());
    }
}
