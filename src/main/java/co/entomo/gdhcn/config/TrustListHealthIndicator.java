package co.entomo.gdhcn.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import co.entomo.gdhcn.util.DidTrustList;

/**
 * Readiness: the service only takes traffic once the public trust list has been loaded. A daemon thread keeps
 * trying every 15 seconds after startup until it succeeds. Not used when the trust list comes from the mTLS API.
 */
@Component("trustList")
public class TrustListHealthIndicator implements HealthIndicator {

	@Autowired
	DidTrustList trustList;
	@Value("${gdhcn.trustlist.mode:did}")
	private String mode;

	@EventListener(ApplicationReadyEvent.class)
	void loadInBackground() {
		if (!"did".equalsIgnoreCase(mode)) {
			return;
		}
		Thread t = new Thread(() -> {
			while (!trustList.tryLoad()) {
				try {
					Thread.sleep(15_000L);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					return;
				}
			}
		}, "trust-list-loader");
		t.setDaemon(true);
		t.start();
	}

	@Override
	public Health health() {
		if (!"did".equalsIgnoreCase(mode)) {
			return Health.up().withDetail("mode", mode).build();
		}
		return trustList.isLoaded() ? Health.up().build() : Health.down().build();
	}
}
