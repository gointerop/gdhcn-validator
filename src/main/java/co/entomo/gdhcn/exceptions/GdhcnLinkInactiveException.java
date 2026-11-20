package co.entomo.gdhcn.exceptions;

/** The link does not exist, has expired, is not passcode-protected, or has used up its passcode attempts: HTTP 404. */
public class GdhcnLinkInactiveException extends GdhcnValidationException {
	public GdhcnLinkInactiveException(String message) {
		super(message);
	}
}
