import { Reflector } from '@nestjs/core';
import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { UserService } from 'src/user/user.service';
import { RequestUserType } from '../interfaces/request-user-type.interface';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
	constructor(
		private readonly userService: UserService,
		private reflector: Reflector
	) {
		super();
	}

	async canActivate(context: ExecutionContext) {
		const isAuthenticated = await super.canActivate(context);

		if (!isAuthenticated) return false;

		const roles = this.reflector.get<string[]>('roles', context.getHandler());

		if (!roles || roles.length === 0) return true;

		const request = context.switchToHttp().getRequest();
		const user = request.user as RequestUserType;

		return this.userService.matchRoles(user.roles, roles);
	}
}
