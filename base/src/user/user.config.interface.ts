export interface UserConfig { 
    maxAge?: number,
    loginType?: LoginType
}

enum LoginType { Email, Username, Phone, TwoFactorAuthentication }