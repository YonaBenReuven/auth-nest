import { Reflector } from '@nestjs/core';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';

import { UserService } from '../../user/user.service';
import { User } from '../../user/user.entity';
import { RequestUserType } from '../interfaces/request-user-type.interface';

export const AuthGuard = (type?: string | string[]) => class AuthGuard {

	static type = type;

	constructor(
		public readonly userService: UserService,
		public readonly reflector: Reflector
	) { }

	async canActivate(context: ExecutionContext) {
		const roles = this.reflector.get<string[]>('roles', context.getHandler());
		const entities = this.reflector.get<Array<typeof User>>('entities', context.getHandler());

		const request = context.switchToHttp().getRequest();
		const user = request.user as RequestUserType;

		const rolesCanActivate = (roles && roles.length > 0) ? this.userService.matchRoles(user.roles, roles) : true;
		const entitiesCanActivate = (entities && entities.length > 0) ? this.userService.matchEntities(user.type, entities) : true;

		let canActivate: boolean;

		if ((!roles || roles.length === 0) && (!entities || entities.length === 0)) canActivate = true;
		else if ((roles && roles.length > 0) && (!entities || entities.length === 0)) canActivate = rolesCanActivate;
		else if ((!roles || roles.length === 0) && (entities && entities.length > 0)) canActivate = entitiesCanActivate;
		else canActivate = rolesCanActivate || entitiesCanActivate;

		if (!canActivate) {
			if (type === 'local' || type === 'jwt' || type === 'knowledge' || type === 'possession') throw new UnauthorizedException();
			else return false;
		}

		return true;
	}
}