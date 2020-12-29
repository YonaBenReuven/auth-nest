import { Provider } from "@nestjs/common";

export interface UserConfig {
	maxAge?: number | string;/** expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms.js).  Eg: 60, "2 days", "10h", "7d" */
	loginType?: LoginType;
	emailVerification?: Boolean;
	providers?: Provider<any>[];
	set_access_logger?: Boolean;
	useUserPassword?: boolean;
	force_change_password_year?: boolean;
	extra_login_fields?: string[];
}

enum LoginType { Email, Username, Phone, TwoFactorAuthentication }