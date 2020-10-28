import { applyDecorators, CanActivate, UseGuards } from '@nestjs/common';

import { User } from '../../user/user.entity';
import { UseAuthGuard } from '../interfaces/use-auth-guard.interface';
import { Roles } from '../decorators/roles.decorator';
import { Entities } from '../decorators/entities.decorator';
import { UseJwtInterceptor } from '../decorators/use-jwt-interceptor.decorator';

import { CreateAuthGuard } from './create-auth-guard.function';

export const createAuthDecorator = (Guard: CanActivate | Function | ReturnType<typeof CreateAuthGuard>): UseAuthGuard => <T extends typeof User>(
	config?: any,
	...rest: any
) => {
	if (!config) return applyDecorators(UseGuards(Guard));

	if (config === '$everyone' && (Guard as ReturnType<typeof CreateAuthGuard>).type === 'jwt') return applyDecorators(
		UseJwtInterceptor()
	);

	if (typeof config === "string") return applyDecorators(
		Roles(config, ...rest as string[]),
		UseGuards(Guard)
	);

	if ((config as { roles: string[] }).roles) return applyDecorators(
		Roles(...((config as { roles: string[] }).roles || [])),
		Entities(...((config as { entities: T[] }).entities || [])),
		UseGuards(Guard)
	);

	return applyDecorators(
		Entities(config as T, ...rest as T[]),
		UseGuards(Guard)
	);
}