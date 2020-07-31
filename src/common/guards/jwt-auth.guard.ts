import { Reflector } from '@nestjs/core';
import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { UserService } from 'src/user/user.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
	constructor(
		private readonly userService: UserService,
		private reflector: Reflector
	) {
		super();
	}

	canActivate(context: ExecutionContext) {
		const isAuthenticated = super.canActivate(context);
		if (!isAuthenticated) return false;

		const roles = this.reflector.get<string[]>('roles', context.getHandler());
		
		if (!roles) return true;
		
		const request = context.switchToHttp().getRequest();
		const user = request.user;
		
		return this.userService.matchRoles(user.roles, roles);
	}
}
