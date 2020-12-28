export interface TwoFactorOptions {
	/**
	 * Number of attempts before user is blocked
	 * @default 3
	 */
	maxAttempts?: number;
	/**
	 * Number of seconds before code is expired
	 * @default 900 (15 min)
	 */
	expires?: number;
	/**
	 * Number of seconds user is blocked after max attempts is reached
	 * @default 600 (10 min)
	 */
	blocked?: number;
	/**
	 * The field in the user object that refers to the user's phone number
	 * @default 'phone'
	 */
	phoneField?: string;
	/**
	 * Length of pin code
	 * @default 4
	 */
	codeLength?: number;
	/**
	 * The sender's name of the SMS
	 */
	SMSSender?: string;
	/**
	 * Send SMS's in development as well as production
	 * @default false
	 */
	sendInDevelopment?: boolean;
	/**
	 * Send SMS's in production
	 * @default true
	 */
	sendInProduction?: boolean;
}