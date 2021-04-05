import { Reflector } from '@nestjs/core';
import { BadRequestException, ExecutionContext, HttpException, Injectable, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';

import { AuthGuard } from '../functions/auth-guard.function';
import { lookup } from '../functions/lookup.function';
import { UserService } from '../../user/user.service';
import { LoginErrorCodes } from '../loginErrorCodes';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {
	constructor(
		public readonly userService: UserService,
		public readonly reflector: Reflector
	) {
		super(userService, reflector);
	}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		try {
			const ctx = context.switchToHttp();
			const request = ctx.getRequest<Request>();

			const username = lookup(request.body, 'username') || lookup(request.query, 'username');
			const password = lookup(request.body, 'password') || lookup(request.query, 'password');

			if (!username || !password) throw new BadRequestException('Missing credentials');

			const user = await this.userService.validateUser(username, password);
			if (!user) throw new UnauthorizedException();

			const userField = this.reflector.getAllAndOverride<string>('userField', [context.getHandler(), context.getClass()]);

			request[userField] = user;

			return super.canActivate(context);

		} catch (error) {
			if (error instanceof HttpException) throw error;

			if (error.key in LoginErrorCodes) throw new UnauthorizedException(error);

			console.error("error in local guard", error);
			throw new UnauthorizedException();
		}
	}
}