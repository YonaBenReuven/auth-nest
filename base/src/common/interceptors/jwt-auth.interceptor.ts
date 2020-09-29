import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Observable } from 'rxjs';

import { jwtConstants } from '../constants';
import { extractTokenFromCookie } from '../functions/extract-token-from-cookie.function';
import { AuthConfig } from '../interfaces/auth-config.interface';

@Injectable()
export class JwtAuthInterceptor implements NestInterceptor {
	constructor(
		private readonly jwtService: JwtService,
		private readonly configService: ConfigService
	) { }

	intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
		const ctx = context.switchToHttp();
		const req = ctx.getRequest<Request>();

		const token = extractTokenFromCookie(this.configService.get<AuthConfig['auth']['accessToken_cookie']>('auth.accessToken_cookie') ?? 'access_token')(req);

		try {
			const user = this.jwtService.verify(token, { secret: this.configService.get<AuthConfig['auth']['secretOrKey']>('auth.secretOrKey') ?? jwtConstants.secret });
			req.user = user;
		} catch (err) {
			req.user = null;
		}

		return next.handle();
	}
}