import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Observable } from 'rxjs';

import { extractTokenFromCookie } from '../functions/extract-token-from-cookie.function';

@Injectable()
export class JwtAuthInterceptor implements NestInterceptor {
	constructor(private readonly jwtService: JwtService) { }

	intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
		const ctx = context.switchToHttp();
		const req = ctx.getRequest<Request>();

		const token = extractTokenFromCookie('access_token')(req);

		try {
			const user = this.jwtService.verify(token);
			req.user = user;
		} catch (err) {
			req.user = null;
		}

		return next.handle();
	}
}