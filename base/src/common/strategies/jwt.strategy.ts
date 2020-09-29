import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-jwt';

import { jwtConstants } from '../constants';
import { extractTokenFromCookie } from '../functions/extract-token-from-cookie.function';
import { AuthConfig } from '../interfaces/auth-config.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(
		private readonly configService: ConfigService,
	) {
		super({
			jwtFromRequest: extractTokenFromCookie('access_token'),
			ignoreExpiration: false,
			secretOrKey: configService.get<AuthConfig['auth']['secretOrKey']>('auth.secretOrKey') ?? jwtConstants.secret,
		});
	}

	async validate(payload: any) {
		return payload;
	}
}
