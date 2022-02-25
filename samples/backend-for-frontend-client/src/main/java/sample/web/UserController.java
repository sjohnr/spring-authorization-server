/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.web;

import java.util.Collections;
import java.util.Map;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Steve Riesenberg
 * @since 0.2.3
 */
@RestController
public class UserController {

	@GetMapping("/userinfo")
	public Mono<Map<String, String>> userInfo(Authentication authentication) {
		return Mono.just(Collections.singletonMap("name", authentication.getName()));
	}

}
