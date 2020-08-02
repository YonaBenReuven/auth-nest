import { applyDecorators, CanActivate, UseGuards } from '@nestjs/common';

import { User } from 'src/user/user.entity';
import { UseAuthGuard } from '../interfaces/use-auth-guard.interface';
import { Roles } from '../decorators/roles.decorator';
import { Entities } from '../decorators/entities.decorator';

export const createAuthDecorator = (Guard: CanActivate | Function): UseAuthGuard => <T extends typeof User>(
	config?: T | string | { roles: string[]; entities: T[] },
	...rest: string[] | T[]
) => {
	if (!config) return applyDecorators(UseGuards(Guard));

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