import { Reflector } from '@nestjs/core';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';

import { RequestUserType } from '../interfaces/request-user-type.interface';
import { UserService } from '../../user/user.service';
import { User } from '../../user/user.entity';

export const AuthGuard = (type?: string | string[]) => class AuthGuard {

	static type = type;

	constructor(
		public readonly userService: UserService,
		public readonly reflector: Reflector
	) { }

	async canActivate(context: ExecutionContext) {
		const roles = this.reflector.getAllAndOverride<string[]>('roles', [context.getHandler(), context.getClass()]);
		const entities = this.reflector.getAllAndOverride<Array<typeof User>>('entities', [context.getHandler(), context.getClass()]);
		const userField = this.reflector.getAllAndOverride<string>('userField', [context.getHandler(), context.getClass()]);

		const request = context.switchToHttp().getRequest<Request>();
		const user = request[userField] as RequestUserType;

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