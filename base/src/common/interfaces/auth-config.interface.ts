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
	};

	app_name?: string;

	app_name_he?: string;

	roleAccessConfig: {
		[role: string]: {
			components: string[];
			defaultHomePage: string;
		};
	};
}