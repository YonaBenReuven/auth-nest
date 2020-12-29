export interface SendCodeOptions {
	/**
	 * Send SMS's in development as well as production
	 */
	sendInDevelopment?: boolean;
	/**
	 * Send SMS's in production
	 * @default true
	 */
	sendInProduction?: boolean;
	/**
	 * Function that generates an SMS message (default to `קוד האימות הוא: ${code}`)
	 */
	SMSGenerator?(code: string): string;
	/**
	 * The code to send to the user
	 */
	code?: string;
	/**
	 * Log the code
	 */
	logCode?: boolean;
	/**
	 * Log the SMS
	 */
	logSMS?: boolean;
}