import { applyDecorators } from '@nestjs/common';

import { UseAuthGuard } from '../interfaces/use-auth-guard.interface';
import { User } from '../../user/user.entity';

import { UserField } from './user-field.decorator';
import { Entities } from './entities.decorator';
import { Roles } from './roles.decorator';

export const SetAuthMetadata: UseAuthGuard = <T extends typeof User>(
	config?: any,
	...rest: any
) => {
	if (!config) return applyDecorators(
		UserField('user'),
		Roles(),
		Entities()
	);

	const userField = (config as { userField: string }).userField || 'user';

	const defaultDecorators = [
		UserField(userField),
		Roles(),
		Entities()
	];

	if (typeof config === "string") return applyDecorators(
		...defaultDecorators,
		Roles(config, ...rest as string[])
	);

	const decorators: Array<ClassDecorator | MethodDecorator> = [];

	if ((config as { roles: string[] }).roles) decorators.push(Roles(...((config as { roles: string[] }).roles)));
	if ((config as { entities: T[] }).entities) decorators.push(Entities(...((config as { entities: T[] }).entities)))

	if (decorators.length > 0) return applyDecorators(
		...defaultDecorators,
		...decorators
	);

	if ((config as { userField: string }).userField) return applyDecorators(
		...defaultDecorators
	);

	if (config) return applyDecorators(
		...defaultDecorators,
		Entities(config as T, ...rest as T[]),
	);

	return applyDecorators(
		...defaultDecorators
	);
}