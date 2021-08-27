package com.example.client;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {
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
	public String authorize(Model model, @RequestParam String code, @RequestParam String state) {
		model.addAttribute("code", code);
		model.addAttribute("state", state);
		model.addAttribute("clientId", this.clientId);
		return "authorized";
	}
}
