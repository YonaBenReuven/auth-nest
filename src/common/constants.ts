import { TwoFactorOptions } from './interfaces/two-factor-options.interface';

export const jwtConstants = {
	secret: 'secretKey',
	twoFactorSecret: 'twoFactorSecretKey'
};

export const SALT = 10;

export const USER_MODULE_OPTIONS = 'USER_MODULE_OPTIONS';

export const TWO_FACTOR_OPTIONS = 'TWO_FACTOR_OPTIONS';

export const defaultTwoFactorOptions: Required<TwoFactorOptions> = {
	maxAttempts: 3,
	expires: 900,
	blocked: 600,
	phoneField: 'phone',
	codeLength: 4,
	SMSSender: 'Hilma',
	sendInDevelopment: false,
	sendInProduction: true
}

export const DEFAULT_MAX_AGE = 1000 * 60 * 60 * 5;

export const EMAIL_VERIFIED = 'emailVerified';

export const VERIFICATION_TOKEN = 'verificationToken';

export const ACCESS_TOKEN = 'access_token';

export const TWO_FACTOR_TOKEN = 'two_factor_token';