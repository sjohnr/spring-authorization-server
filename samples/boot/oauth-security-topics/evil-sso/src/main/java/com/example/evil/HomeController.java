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

	@GetMapping("/authorize")
	public String authorize(Model model,  @RequestParam String code) {
		model.addAttribute("code", code);
		return "authorize";
	}
}
