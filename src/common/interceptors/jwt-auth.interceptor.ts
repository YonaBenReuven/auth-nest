import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Observable } from 'rxjs';

import { jwtConstants } from '../constants';
import { extractTokenFromCookie } from '../functions/extract-token-from-cookie.function';
import { AuthConfigAccessTokenCookie, AuthConfigQueryAccessToken, AuthConfigSecretOrKey } from '../interfaces/auth-config.interface';

@Injectable()
export class JwtAuthInterceptor implements NestInterceptor {
	constructor(
		private readonly jwtService: JwtService,
		private readonly configService: ConfigService,
		private readonly reflector: Reflector
	) { }

	intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
		const ctx = context.switchToHttp();
		const request = ctx.getRequest<Request>();

		const token = extractTokenFromCookie(
			this.configService.get<AuthConfigAccessTokenCookie>('auth.accessToken_cookie') ?? 'access_token',
			this.configService.get<AuthConfigQueryAccessToken>('auth.allow_accessToken_query') ?? false
		)(request);

		const userField = this.reflector.getAllAndOverride<string>('userField', [context.getHandler(), context.getClass()]);

		try {
			const user = this.jwtService.verify(token, { secret: this.configService.get<AuthConfigSecretOrKey>('auth.secretOrKey') ?? jwtConstants.secret });

			request[userField] = user;
		} catch (err) {
			request[userField] = null;
		}

		return next.handle();
	}
}