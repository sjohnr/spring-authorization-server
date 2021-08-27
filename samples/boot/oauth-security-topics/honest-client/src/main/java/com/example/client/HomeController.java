package com.example.client;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {
	@GetMapping("/")
	public String home() {
		return "redirect:http://honest-client:8080/index";
	}

	@GetMapping("/index")
	public String index() {
		return "index";
	}

	@GetMapping("/honest")
	public String honest(Model model, @RequestParam(required = false) String code, @RequestParam(required = false) String state) {
		model.addAttribute("code", code);
		model.addAttribute("state", state);
		return "honest";
	}

	@GetMapping("/evil")
	public String evil() {
		return "evil";
	}
}
