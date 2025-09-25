package com.ppublica.shopify.app.entrypoint;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class AppEntryController {

    @RequestMapping("/app/**")
    public String forwardToAppEntryPage() {
        return "forward:/index.html";
    }
}
