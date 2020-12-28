
export const LoginErrorCodes: ErrorDictonery = {
	PassDosentMatch: { key: "PassDosentMatch", code: 1, message: "Wrong password" },
	NoUsername: { key: "NoUsername", code: 2, message: "User doesn't exist" },
	EmailNotVerified: { key: "EmailNotVerified", code: 3, message: "Email must be verified" },
	UserBlocked: { key: "UserBlocked", code: 4, message: "Too many login attemps. You must wait" },
	UserHasNoPassword: { key: "UserHasNoPassword", code: 5, message: "Invalid login" }, // this happens when he logges in with google or other platforms
	UserIsBlocked: { key: "UserIsBlocked", code: 6, message: "User is blocked" },
	MaxAttempts: { key: "MaxAttempts", code: 7, message: "Max attempts" },
	CodeHasExpired: { key: "CodeHasExpired", code: 8, message: "Code has expired" },
	IncorrectCode: { key: "IncorrectCode", code: 9, message: "Incorrect code" }
}

interface ErrorDictonery {
	[name: string]: { code: number, message: string, key: string }
}