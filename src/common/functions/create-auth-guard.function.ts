import { Reflector } from '@nestjs/core';
import { ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { UserService } from 'src/user/user.service';
import { RequestUserType } from '../interfaces/request-user-type.interface';
import { User } from 'src/user/user.entity';

export const CreateAuthGuard = (type?: string | string[]) => class CreateAuthGuard extends AuthGuard(type) {
	constructor(
		public readonly userService: UserService,
		public readonly reflector: Reflector
	) {
		super();
	}

	async canActivate(context: ExecutionContext) {
		const isAuthenticated = await super.canActivate(context);

		if (!isAuthenticated) return false;

		const entities = this.reflector.get<Array<typeof User>>('entities', context.getHandler());
		const roles = this.reflector.get<string[]>('roles', context.getHandler());

		const request = context.switchToHttp().getRequest();
		const user = request.user as RequestUserType;

		return ((entities && entities.length > 0) ? this.userService.matchEntities(user.type, entities) : true) &&
			((roles && roles.length > 0) ? this.userService.matchRoles(user.roles, roles) : true);
	}
}