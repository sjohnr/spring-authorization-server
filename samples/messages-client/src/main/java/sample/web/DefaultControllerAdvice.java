package sample.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
public class DefaultControllerAdvice {

	@ModelAttribute("currentUser")
	public OidcUser currentUser(@AuthenticationPrincipal OidcUser user) {
		return user;
	}

}