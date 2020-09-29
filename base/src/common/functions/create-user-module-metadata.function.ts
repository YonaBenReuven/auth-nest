import { ModuleMetadata } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';

import { UserConfig } from '../../user/user.config.interface';
import { RoleModule } from '../../role/role.module';
import { User } from '../../user/user.entity';
import { UserService } from '../../user/user.service';

import { jwtConstants, USER_MODULE_OPTIONS } from '../constants';
import { LocalStrategy } from '../strategies/local.strategy';
import { JwtStrategy } from '../strategies/jwt.strategy';

export const createUserModuleMetadata = (
	options: UserConfig = {}
): ModuleMetadata => ({
	imports: [
		RoleModule,
		TypeOrmModule.forFeature([User]),
		JwtModule.register({
			secret: jwtConstants.secret,
			signOptions: { expiresIn: options.maxAge || '100min' },
		})
	],
	providers: [
		{
			provide: USER_MODULE_OPTIONS,
			useValue: options,
		},
		UserService, LocalStrategy, JwtStrategy,
		...(options.providers || [])
	],
	exports: [UserService]
});