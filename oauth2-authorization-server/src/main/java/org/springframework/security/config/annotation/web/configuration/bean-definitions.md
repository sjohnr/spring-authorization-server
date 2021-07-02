Bean Definitions
===

Discussion on how to register bean definitions in Spring Authorization Server.

Option 1
---

Register via `BeanDefinitionRegistryPostProcessor`:

### Step 1: Create post processor

The post processor would need to introspect the bean definition registry to determine if a given bean should be registered, and then register it if necessary.

For example:

```java
/**
 * Post processor to register one or more bean definitions on container initialization, if not already present.
 *
 * @author Steve Riesenberg
 * @since 0.2.0
 */
final class AuthorizationServerBeanDefinitionRegistryPostProcessor implements BeanDefinitionRegistryPostProcessor, BeanFactoryAware {

	private final AnnotationBeanNameGenerator beanNameGenerator = new AnnotationBeanNameGenerator();
	private final List<AbstractBeanDefinition> beanDefinitions = new ArrayList<>();

	private BeanFactory beanFactory;

	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
		for (AbstractBeanDefinition beanDefinition : beanDefinitions) {
			String[] beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
					(ListableBeanFactory) this.beanFactory, beanDefinition.getBeanClass(), false, false);
			if (beanNames.length == 0) {
				String beanName = beanNameGenerator.generateBeanName(beanDefinition, registry);
				registry.registerBeanDefinition(beanName, beanDefinition);
			}
		}
	}

	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
	}

	void registerBeanDefinition(Class<?> beanDefinitionClass) {
		AbstractBeanDefinition beanDefinition = BeanDefinitionBuilder
				.genericBeanDefinition(beanDefinitionClass)
				.getBeanDefinition();
		beanDefinitions.add(beanDefinition);
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.beanFactory = beanFactory;
	}

}
```

### Step 2: Register the post processor

Using this technique, we can add classes that we would like to register, and wire up the post processor with Spring.

For example:

```java
@Configuration
public class SomeConfig {

    @Bean
    public AuthorizationServerBeanDefinitionRegistryPostProcessor authorizationServerBeanDefinitionRegistryPostProcessor() {
        AuthorizationServerBeanDefinitionRegistryPostProcessor postProcessor =
                new AuthorizationServerBeanDefinitionRegistryPostProcessor();
        postProcessor.registerBeanDefinition(ProviderSettings.class);
        return postProcessor;
    }

}
```

Option 2
---

Use `@Conditional` which is built into Spring and already supports this and similar cases.

### Step 1: Create condition

Similar to the `BeanDefinitionRegistryPostProcessor`, the condition would need to introspect the bean definition registry to determine if a given bean is missing.

For example:

```java
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
```

### Step 2: Declare the bean

Unlike the post processor, this technique does not actually need to register the bean, but only relies on a `@Configuration` to declare it.

For example:

```java
@Configuration
public class SomeConfig {

    @Bean
    @Conditional(MissingBeanDefinitionCondition.OnMissingProviderSettings.class)
    public ProviderSettings providerSettings() {
        return new ProviderSettings();
    }

}
```

Other options
---

TODO

Discussion
---

Both techniques face a same challenge: How to register something with the container.

In both cases, we have to make sure that the Spring IoC container is initializing and sees our bean (whether our `BeanDefinitionRegistryPostProcessor` or our `@Conditional` `@Bean`). The problem and solution are likely the same in both cases. See below.

Option 1 could be useful if we can get access to the application context, but do not want to declare a Java configuration class. For example, if the `OAuth2AuthorizationServerConfigurer` could somehow get a handle on the `ApplicationContext`, we would not need to rely on an `@Configuration`.

Option 2 is more useful when applied to a wider range of possible beans we want to register, because the Java configuration class could create them using any initialization logic deemed necessary. No need to define abstractions in the post processor for complicated cases. Simply declare the `@Bean` as `@Conditional` and it is registered if not provided by the application.

Solutions
---

The main problem mentioned above surrounds finding a way to bootstrap our bean while the Spring IoC container is initializing. I'm not aware of any new or novel ways of doing this. The two that come to mind (which we've seen before) are:

1. Use `spring.factories` to register an auto-configuration.
2. Use a meta-annotation to `@Import` our configuration.

The first option relies on spring boot, which may not be ideal. The second option moves toward to the old `@EnableAuthorizationServer` or similar annotation which was available with the old `spring-security-oauth2` package.

Other options:

3. Add auto-configuration support to `spring-boot-autoconfigure`.
4. Add spring authorization server to `spring-security` itself, and auto-configure based on introspecting the classpath in `spring-security-config`.

Other Solutions
---

TODO
