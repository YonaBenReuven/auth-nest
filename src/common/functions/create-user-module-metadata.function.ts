import { ModuleMetadata } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';

import { UserConfig } from '../../user/user.config.interface';
import { RoleModule } from '../../role/role.module';
import { User } from '../../user/user.entity';
import { UserService } from '../../user/user.service';

import { USER_MODULE_OPTIONS } from '../constants';
import { AccessLoggerModule } from '../../access-logger';
import { UserPasswordModule } from '../../user-password/user-password.module';

export const createUserModuleMetadata = (
	options: UserConfig = {}
): ModuleMetadata => ({
	imports: [
		RoleModule,
		TypeOrmModule.forFeature([User]),
		JwtModule.register({}),
		...(options.set_access_logger && [AccessLoggerModule] || []),
		...(options.useUserPassword && [UserPasswordModule] || [])
	],
	providers: [
		{
			provide: USER_MODULE_OPTIONS,
			useValue: options,
		},
		UserService,
		...(options.providers || [])
	],
	exports: [UserService]
});