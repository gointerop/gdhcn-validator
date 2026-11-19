package co.entomo.gdhcn.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Passcodes (PINs) are stored only as Argon2id hashes. */
@Configuration
public class PinConfiguration {

	@Bean
	public PasswordEncoder pinEncoder() {
		return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
	}
}
