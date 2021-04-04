import { applyDecorators, CanActivate, UseGuards } from '@nestjs/common';

import { UseJwtInterceptor } from '../decorators/use-jwt-interceptor.decorator';
import { UseAuthGuard } from '../interfaces/use-auth-guard.interface';
import { UserField } from '../decorators/user-field.decorator';
import { Entities } from '../decorators/entities.decorator';
import { Roles } from '../decorators/roles.decorator';
import { User } from '../../user/user.entity';

import { AuthGuard } from './auth-guard.function';

export const createAuthDecorator = (Guard: CanActivate | Function | ReturnType<typeof AuthGuard>): UseAuthGuard => <T extends typeof User>(
	config?: any,
	...rest: any
) => {
	if (!config) return applyDecorators(UseGuards(Guard));

	if (config === '$everyone' && (Guard as ReturnType<typeof AuthGuard>).type === 'jwt') return applyDecorators(
		UseJwtInterceptor()
	);

	const userField = (config as { userField: string }).userField || 'user';

	const defaultDecorators = [
		UserField(userField),
		UseGuards(Guard)
	];

	if (typeof config === "string") return applyDecorators(
		Roles(config, ...rest as string[]),
		...defaultDecorators
	);

	const decorators: Array<ClassDecorator | MethodDecorator> = [];

	if ((config as { roles: string[] }).roles) decorators.push(Roles(...((config as { roles: string[] }).roles)));
	if ((config as { entities: T[] }).entities) decorators.push(Entities(...((config as { entities: T[] }).entities)))

	if (decorators.length > 0) return applyDecorators(
		...decorators,
		...defaultDecorators
	);

	if (config) return applyDecorators(
		Entities(config as T, ...rest as T[]),
		...defaultDecorators
	);

	return applyDecorators(
		...defaultDecorators
	);
}