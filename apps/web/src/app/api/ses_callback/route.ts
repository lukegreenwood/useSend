import { env } from "~/env";
import { validateSnsSignature } from "~/lib/sns-validator";
import { db } from "~/server/db";
import { logger } from "~/server/logger/log";
import { parseSesHook, SesHookParser } from "~/server/service/ses-hook-parser";
import { SesSettingsService } from "~/server/service/ses-settings-service";
import { SnsNotificationMessage } from "~/types/aws-types";

export const dynamic = "force-dynamic";

export async function GET() {
	return Response.json({ data: "Hello" });
}

export async function POST(req: Request) {
	const data = await req.json();

	console.log(data, data.Message);

	const isEventValid = await checkEventValidity(data);

	console.log("Is event valid: ", isEventValid);

	if (!isEventValid) {
		return Response.json({ data: "Event is not valid" });
	}

	if (data.Type === "SubscriptionConfirmation") {
		return handleSubscription(data);
	}

	let message = null;

	try {
		message = JSON.parse(data.Message || "{}");
		const status = await SesHookParser.queue({
			event: message,
			messageId: data.MessageId,
		});
		if (!status) {
			return Response.json({ data: "Error in parsing hook" });
		}

		return Response.json({ data: "Success" });
	} catch (e) {
		console.error(e);
		return Response.json({ data: "Error is parsing hook" });
	}
}

/**
 * Handles the subscription confirmation event. called only once for a webhook
 */
async function handleSubscription(message: any) {
	await fetch(message.SubscribeURL, {
		method: "GET",
	});

	const topicArn = message.TopicArn as string;
	const setting = await db.sesSetting.findFirst({
		where: {
			topicArn,
		},
	});

	if (!setting) {
		return Response.json({ data: "Setting not found" });
	}

	await db.sesSetting.update({
		where: {
			id: setting?.id,
		},
		data: {
			callbackSuccess: true,
		},
	});

	SesSettingsService.invalidateCache();

	return Response.json({ data: "Success" });
}

/**
 * Validates the SNS message by checking:
 * 1. The cryptographic signature (ensures message is from AWS SNS)
 * 2. The TopicArn matches a configured topic
 */
async function checkEventValidity(message: SnsNotificationMessage) {
	// Skip validation in development for easier testing
	if (env.NODE_ENV === "development") {
		return true;
	}

	// Validate the SNS signature first (cryptographic verification)
	const isSignatureValid = await validateSnsSignature(message);
	if (!isSignatureValid) {
		console.error("SNS signature validation failed");
		return false;
	}

	// Then verify the TopicArn is one we expect
	const { TopicArn } = message;
	const configuredTopicArn = await SesSettingsService.getTopicArns();

	if (!configuredTopicArn.includes(TopicArn)) {
		console.error(`Unexpected TopicArn: ${TopicArn}`);
		return false;
	}

	return true;
}
