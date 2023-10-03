package br.com.vicente.authjwt.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {


    @GetMapping
    public ResponseEntity<String> sayHello(){
        return ResponseEntity.ok("Hello");
    }
}
