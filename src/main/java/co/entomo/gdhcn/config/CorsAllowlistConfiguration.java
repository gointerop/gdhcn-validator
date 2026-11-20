package co.entomo.gdhcn.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * CORS for the two endpoints a browser viewer calls after reading the QR: the manifest and the IPS download.
 * Only the origins listed in {@code vhl.cors.allowed-origins} (comma separated) are allowed; with the setting empty no
 * CORS header is sent, which is right when the viewer and the service share one origin behind the same host.
 */
@Configuration
public class CorsAllowlistConfiguration implements WebMvcConfigurer {

	@Value("${vhl.cors.allowed-origins:}")
	private String allowedOrigins;

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		if (!StringUtils.hasText(allowedOrigins)) {
			return;
		}
		String[] origins = StringUtils.tokenizeToStringArray(allowedOrigins, ",");
		registry.addMapping("/v2/manifests/**").allowedOrigins(origins).allowedMethods("POST", "OPTIONS")
				.allowedHeaders("Content-Type", "Accept").maxAge(3600);
		registry.addMapping("/v2/ips-json/**").allowedOrigins(origins).allowedMethods("GET", "OPTIONS")
				.allowedHeaders("Content-Type", "Accept").maxAge(3600);
	}
}
