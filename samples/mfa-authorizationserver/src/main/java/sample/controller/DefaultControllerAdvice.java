/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.controller;

import sample.model.UserInfo;
import sample.security.CurrentUser;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * @author Steve Riesenberg
 */
@ControllerAdvice
public class DefaultControllerAdvice {

	@ModelAttribute("currentUser")
	public UserInfo currentUser(@CurrentUser UserInfo currentUser) {
		return (currentUser != null) ? currentUser : new UserInfo(null, null, null, null, null, null, "pepperoni");
	}

}