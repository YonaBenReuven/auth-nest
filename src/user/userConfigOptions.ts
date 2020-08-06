export default class UserConfigOptions {
    constructor(obj: UserConfigOptions = {}) {
        this.emailVerification = obj.emailVerification;
        this.emailAddress = obj.emailAddress;
        this.fromName = obj.fromName;
        this.mailer = obj.mailer;
        this.verifyPath = obj.verifyPath || "/user/verify";
        this.pathToLogo = obj.pathToLogo;
        this.OAuth2 = obj.OAuth2;//or false
    }

    emailVerification?: Boolean;
    mailer?: any;
    emailAddress?: string;
    fromName?: string;
    verifyPath?: string;
    pathToLogo?: string;
    OAuth2?: boolean;
}