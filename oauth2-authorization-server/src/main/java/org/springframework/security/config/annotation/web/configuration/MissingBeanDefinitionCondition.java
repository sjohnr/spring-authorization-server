/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.ConfigurationCondition;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.util.Assert;

/**
 * Simple condition for detecting missing bean definitions.
 *
 * @author Steve Riesenberg
 * @since 0.2.0
 */
class MissingBeanDefinitionCondition implements ConfigurationCondition {

	private final Class<?> beanDefinitionClass;

	MissingBeanDefinitionCondition(Class<?> beanDefinitionClass) {
		this.beanDefinitionClass = beanDefinitionClass;
	}

	@Override
	public ConfigurationPhase getConfigurationPhase() {
		return ConfigurationPhase.REGISTER_BEAN;
	}

	@Override
	public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
		ConfigurableListableBeanFactory beanFactory = context.getBeanFactory();
		Assert.notNull(beanFactory, "beanFactory is not available");
		String[] beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
				beanFactory, beanDefinitionClass, false, false);
		return beanNames.length == 0;
	}

	/**
	 * Condition for detecting missing {@link ProviderSettings} bean definition.
	 *
	 * @author Steve Riesenberg
	 * @since 0.2.0
	 */
	static class OnMissingProviderSettings extends MissingBeanDefinitionCondition {

		OnMissingProviderSettings() {
			super(ProviderSettings.class);
		}

	}

}
