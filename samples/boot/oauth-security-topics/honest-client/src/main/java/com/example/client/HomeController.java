package com.example.client;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

@Controller
public class HomeController {
	private static final Map<String, String> SERVER_URLS = new HashMap<>();
	static {
		SERVER_URLS.put("honest-client", "http://honest-sso:9000");
		SERVER_URLS.put("evil-client", "http://evil-sso:8090");
	}

	private String clientId;

	@GetMapping("/")
	public String home() {
		return "redirect:http://honest-client:8080/index";
	}

	@GetMapping("/index")
	public String index() {
		return "index";
	}

	@GetMapping("/honest")
	public String honest() {
		this.clientId = "honest-client";
		return "honest";
	}

	@GetMapping("/evil")
	public String evil() {
		this.clientId = "evil-client";
		return "evil";
	}

	@GetMapping("/authorized")
	public String authorize(Model model, @RequestParam(required = false) String code, @RequestParam(required = false) String state) {
		model.addAttribute("code", code);
		model.addAttribute("state", state);
		return "authorized";
	}

	@PostMapping("/authorized")
	public String getToken(Model model, @RequestParam String code) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add("grant_type", "authorization_code");
		parameters.add("code", code);
		parameters.add("redirect_uri", "http://honest-client:8080/authorized");

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		headers.setBasicAuth("honest-client", "secret");

		String baseUrl = SERVER_URLS.get(this.clientId);
		RequestEntity<MultiValueMap<String, String>> requestEntity = new RequestEntity<>(parameters, headers, HttpMethod.POST, URI.create(baseUrl + "/oauth2/token"));
		RestTemplate restTemplate = new RestTemplate();
		ResponseEntity<Map<String, String>> responseEntity = restTemplate.exchange(requestEntity, new ParameterizedTypeReference<Map<String, String>>() {});
		model.addAttribute("accessToken", responseEntity.getBody().get("access_token"));

		return "authorized";
	}
}
