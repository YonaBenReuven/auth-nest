interface ErrorDictonery {
	[name: string]: {
		code: number;
		message: string;
		key: string;
	};
}

const createLoginErrorCodes = <T extends ErrorDictonery>(errorCodes: T): T => errorCodes;

export const LoginErrorCodes = createLoginErrorCodes({
	PassDosentMatch: { key: "PassDosentMatch", code: 1, message: "Wrong password" },
	NoUsername: { key: "NoUsername", code: 2, message: "User doesn't exist" },
	EmailNotVerified: { key: "EmailNotVerified", code: 3, message: "Email must be verified" },
	UserBlocked: { key: "UserBlocked", code: 4, message: "Too many login attemps. You must wait" },
	UserHasNoPassword: { key: "UserHasNoPassword", code: 5, message: "Invalid login" }, // this happens when he logges in with google or other platforms
	UserMustChangePassword: { key: "UserMustChangePassword", code: 6, message: "A year have pass since the last time you changed your password. Please change it." },
	UserIsBlocked: { key: "UserIsBlocked", code: 7, message: "User is blocked" },
	MaxAttempts: { key: "MaxAttempts", code: 8, message: "Max attempts" },
	CodeHasExpired: { key: "CodeHasExpired", code: 9, message: "Code has expired" },
	IncorrectCode: { key: "IncorrectCode", code: 10, message: "Incorrect code" }
});