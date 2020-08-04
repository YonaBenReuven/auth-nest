export default class UserConfigOptions {
    constructor(obj: UserConfigOptions = {}) {
        this.emailVerification = obj.emailVerification;
        this.emailAddress = obj.emailAddress;
        this.fromName = obj.fromName;
        this.mailer = obj.mailer;
        this.verifyPath = obj.verifyPath || "/user/verify";
        this.pathToLogo = obj.pathToLogo;

    }

    emailVerification?: Boolean
    mailer?: any
    emailAddress?: string
    fromName?: string
    verifyPath?: string;
    pathToLogo?: string
}