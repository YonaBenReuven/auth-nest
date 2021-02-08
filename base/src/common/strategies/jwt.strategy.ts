import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-jwt';

import { jwtConstants } from '../constants';
import { extractTokenFromCookie } from '../functions/extract-token-from-cookie.function';
import { AuthConfigAccessTokenCookie, AuthConfigQueryAccessToken, AuthConfigSecretOrKey } from '../interfaces/auth-config.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(
		private readonly configService: ConfigService,
	) {
		super({
			jwtFromRequest: extractTokenFromCookie(
				configService.get<AuthConfigAccessTokenCookie>('auth.accessToken_cookie') ?? 'access_token',
				configService.get<AuthConfigQueryAccessToken>('auth.allow_accessToken_query') ?? false),
			ignoreExpiration: false,
			secretOrKey: configService.get<AuthConfigSecretOrKey>('auth.secretOrKey') ?? jwtConstants.secret,
		});
	}

	async validate(payload: any) {
		return payload;
	}
}
