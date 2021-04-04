import { Reflector } from '@nestjs/core';
import { ExecutionContext, HttpException, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

import { AuthConfigAccessTokenCookie, AuthConfigQueryAccessToken } from '../interfaces/auth-config.interface';
import { extractTokenFromCookie } from '../functions/extract-token-from-cookie.function';
import { AuthGuard } from '../functions/auth-guard.function';
import { UserService } from '../../user/user.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {

	jwtFromRequest: (request: Request) => any;

	constructor(
		public readonly userService: UserService,
		public readonly reflector: Reflector,
		public readonly configService: ConfigService
	) {
		super(userService, reflector);

		this.jwtFromRequest = extractTokenFromCookie(
			configService.get<AuthConfigAccessTokenCookie>('auth.accessToken_cookie') ?? 'access_token',
			configService.get<AuthConfigQueryAccessToken>('auth.allow_accessToken_query') ?? false
		);
	}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		try {
			const ctx = context.switchToHttp();
			const request = ctx.getRequest<Request>();

			const userField = this.reflector.get<string>('userField', context.getHandler()) || 'user';

			const accessToken = this.jwtFromRequest(request);

			const user = await this.userService.verifyAccessToken(accessToken, {
				ignoreExpiration: false
			});

			request[userField] = user;

			return super.canActivate(context);
		} catch (error) {
			if (error instanceof HttpException) throw error;
			throw new UnauthorizedException();
		}
	}
}