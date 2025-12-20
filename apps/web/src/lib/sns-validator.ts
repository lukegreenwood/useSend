import { createVerify } from "crypto";
import { logger } from "~/server/logger/log";
import { SnsNotificationMessage } from "~/types/aws-types";

// Cache certificates to avoid repeated fetches
const certificateCache = new Map<string, { cert: string; expires: number }>();
const CERT_CACHE_TTL = 1000 * 60 * 60; // 1 hour

// Valid AWS SNS signing certificate URL patterns
const VALID_CERT_URL_PATTERNS = [
	/^https:\/\/sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?\/SimpleNotificationService-[a-f0-9]+\.pem$/,
];

/**
 * Validates that the SigningCertURL is from a legitimate AWS domain
 */
function isValidCertUrl(url: string): boolean {
	try {
		const parsedUrl = new URL(url);

		// Must be HTTPS
		if (parsedUrl.protocol !== "https:") {
			return false;
		}

		// Must match AWS SNS certificate URL pattern
		return VALID_CERT_URL_PATTERNS.some((pattern) => pattern.test(url));
	} catch {
		return false;
	}
}

/**
 * Fetches and caches the signing certificate from AWS
 */
async function fetchCertificate(certUrl: string): Promise<string> {
	const cached = certificateCache.get(certUrl);
	if (cached && cached.expires > Date.now()) {
		return cached.cert;
	}

	const response = await fetch(certUrl);
	if (!response.ok) {
		throw new Error(`Failed to fetch certificate: ${response.statusText}`);
	}

	const cert = await response.text();

	certificateCache.set(certUrl, {
		cert,
		expires: Date.now() + CERT_CACHE_TTL,
	});

	return cert;
}

/**
 * Builds the string to sign based on the message type
 * SNS uses specific fields in a specific order depending on message type
 */
function buildStringToSign(message: SnsNotificationMessage): string {
	const fields: string[] = [];

	if (message.Type === "Notification") {
		// For Notification messages
		fields.push("Message");
		fields.push(message.Message);
		fields.push("MessageId");
		fields.push(message.MessageId);

		if (message.Subject) {
			fields.push("Subject");
			fields.push(message.Subject);
		}

		fields.push("Timestamp");
		fields.push(message.Timestamp);
		fields.push("TopicArn");
		fields.push(message.TopicArn);
		fields.push("Type");
		fields.push(message.Type);
	} else if (
		message.Type === "SubscriptionConfirmation" ||
		message.Type === "UnsubscribeConfirmation"
	) {
		// For subscription confirmation messages
		fields.push("Message");
		fields.push(message.Message);
		fields.push("MessageId");
		fields.push(message.MessageId);
		fields.push("SubscribeURL");
		fields.push(message.SubscribeURL ?? "");
		fields.push("Timestamp");
		fields.push(message.Timestamp);
		fields.push("Token");
		fields.push(message.Token ?? "");
		fields.push("TopicArn");
		fields.push(message.TopicArn);
		fields.push("Type");
		fields.push(message.Type);
	} else {
		throw new Error(`Unknown message type: ${message.Type}`);
	}

	return fields.join("\n") + "\n";
}

/**
 * Validates an SNS message signature
 * Returns true if valid, false otherwise
 */
export async function validateSnsSignature(
	message: SnsNotificationMessage
): Promise<boolean> {
	try {
		if (message.SignatureVersion !== "1") {
			logger.error({
				msg: `Unsupported SignatureVersion: ${message.SignatureVersion}`,
			});
			return false;
		}

		if (!isValidCertUrl(message.SigningCertURL)) {
			logger.error({
				msg: `Invalid SigningCertURL: ${message.SigningCertURL}`,
			});
			return false;
		}

		const certificate = await fetchCertificate(message.SigningCertURL);

		const stringToSign = buildStringToSign(message);

		const signature = Buffer.from(message.Signature, "base64");

		const verifier = createVerify("SHA1");
		verifier.update(stringToSign, "utf8");

		return verifier.verify(certificate, signature);
	} catch (error) {
		logger.error({ err: error, msg: "Error validating SNS signature" });
		return false;
	}
}

/**
 * Clears the certificate cache (useful for testing)
 */
export function clearCertificateCache(): void {
	certificateCache.clear();
}
