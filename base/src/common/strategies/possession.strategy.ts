import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { Strategy } from 'passport-jwt';

import { UserService } from '../../user/user.service';
import { TwoFactorService } from '../../two-factor/two-factor.service';

import { jwtConstants, TWO_FACTOR_TOKEN } from '../constants';
import { AuthConfigTwoFactorTokenCookie, AuthConfigTwoFactorSecretOrKey } from '../interfaces/auth-config.interface';
import { RequestUserType } from '../interfaces/request-user-type.interface';
import { LoginErrorCodes } from '../loginErrorCodes';

@Injectable()
export class PossessionStrategy extends PassportStrategy(Strategy, 'possession') {
	constructor(
		private readonly configService: ConfigService,
		private readonly twoFactorService: TwoFactorService,
		private readonly userService: UserService
	) {
		super({
			jwtFromRequest: (req: Request) => req.body[configService.get<AuthConfigTwoFactorTokenCookie>('auth.twoFactorToken_cookie') ?? TWO_FACTOR_TOKEN],
			ignoreExpiration: true,
			secretOrKey: configService.get<AuthConfigTwoFactorSecretOrKey>('auth.twoFactorSecretOrKey') ?? jwtConstants.twoFactorSecret,
			passReqToCallback: true
		});
	}

	async validate(req: Request, payload: RequestUserType) {
		try {
			if (!payload || !req.body.code) throw new UnauthorizedException();

			await this.twoFactorService.validateCode(payload.id, req.body.code);

			const user = await this.userService.validateUser(payload.username, undefined, false);
			if (!user) throw new UnauthorizedException();
			return user;
		} catch (err) {
			if (err.key in LoginErrorCodes)
				throw new UnauthorizedException(err);
			else {
				console.error("error in possession strategy", err);
				throw new UnauthorizedException();
			}
		}
	}
}
