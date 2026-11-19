package co.entomo.gdhcn.exceptions;

/** Wrong or missing passcode: HTTP 401 with {@code {"remainingAttempts": n}} (HL7 SMART Health Links). */
public class GdhcnInvalidPasscodeException extends GdhcnValidationException {
	private final int remainingAttempts;

	public GdhcnInvalidPasscodeException(int remainingAttempts) {
		super("Invalid passcode");
		this.remainingAttempts = remainingAttempts;
	}

	public int getRemainingAttempts() {
		return remainingAttempts;
	}
}
