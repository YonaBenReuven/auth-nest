export interface AuthConfig {
	auth: {
		ttl?: {
			[type: string]: number;
		};

		verification_email?: {
			welcome_to?: string;
			verifyPath?: string;
			html?: string;
			text?: string;
			logoDiv?: string;
			logoPath?: string;
			subject?: string;
		};

		secretOrKey?: string;

		accessToken_cookie?: string
	};

	app_name?: string;

	app_name_he?: string;

	roleAccess: {
		[role: string]: {
			components: string[];
			defaultHomePage: string;
		};
	};
}

export type AuthConfigTtl = AuthConfig['auth']['ttl'];

export type AuthConfigVerificationEmail = AuthConfig['auth']['verification_email'];

export type AuthConfigSecretOrKey = AuthConfig['auth']['secretOrKey'];

export type AuthConfigAccessTokenCookie = AuthConfig['auth']['accessToken_cookie'];

export type AuthConfigAppName = AuthConfig['app_name'];

export type AuthConfigAppNameHe = AuthConfig['app_name_he'];

export type AuthConfigRoleAccess = AuthConfig['roleAccess'];