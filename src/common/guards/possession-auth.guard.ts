import { Reflector } from '@nestjs/core';
import { BadRequestException, ExecutionContext, HttpException, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

import { AuthGuard } from '../functions/auth-guard.function';
import { lookup } from '../functions/lookup.function';
import { UserService } from '../../user/user.service';
import { LoginErrorCodes } from '../loginErrorCodes';
import { TwoFactorService } from '../../two-factor/two-factor.service';
import { AuthConfigTwoFactorTokenCookie } from '../interfaces/auth-config.interface';
import { TWO_FACTOR_TOKEN } from '../constants';

@Injectable()
export class PossessionAuthGuard extends AuthGuard('possession') {

	twoFactorCookie: string;

	constructor(
		public readonly userService: UserService,
		private readonly twoFactorService: TwoFactorService,
		public readonly configService: ConfigService,
		public readonly reflector: Reflector
	) {
		super(userService, reflector);

		this.twoFactorCookie = configService.get<AuthConfigTwoFactorTokenCookie>('auth.twoFactorToken_cookie', TWO_FACTOR_TOKEN);
	}

	jwtFromRequest(request: Request): any {
		return request.body[this.twoFactorCookie];
	}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		try {
			const ctx = context.switchToHttp();
			const request = ctx.getRequest<Request>();

			const code = lookup(request.body, 'code') || lookup(request.query, 'code');
			if (!code) throw new BadRequestException('Missing credentials');

			const twoFactorToken = this.jwtFromRequest(request);

			const payload = await this.twoFactorService.verifyTwoFactorToken(twoFactorToken, {
				ignoreExpiration: true
			});
			await this.twoFactorService.validateCode(payload.id, code);

			const user = await this.userService.validateUser(payload.username, undefined, false);
			if (!user) throw new UnauthorizedException();

			await this.twoFactorService.validateUser(user.id);

			const userField = this.reflector.getAllAndOverride<string>('userField', [context.getHandler(), context.getClass()]);

			request[userField] = user;

			return super.canActivate(context);

		} catch (error) {
			if (error instanceof HttpException) throw error;

			if (error.key in LoginErrorCodes) throw new UnauthorizedException(error);

			console.error("error in possession guard", error);
			throw new UnauthorizedException();
		}
	}
}