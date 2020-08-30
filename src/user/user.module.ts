import { Module, DynamicModule } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';

import { jwtConstants } from 'src/common/constants';
import { LocalStrategy } from 'src/common/strategies/local.strategy';
import { JwtStrategy } from 'src/common/strategies/jwt.strategy';
import { RoleModule } from 'src/role/role.module';
import { UserService } from './user.service';
import { User } from './user.entity';
import { UserConfig } from 'src/user/user.config.interface';

const module = (options: UserConfig = {}) => ({
	imports: [
		RoleModule,
		TypeOrmModule.forFeature([User]),
		JwtModule.register({
			secret: jwtConstants.secret,
			signOptions: { expiresIn: '100min' },
		})
	],
	providers: [
		{
			provide: 'CONFIG_OPTIONS',
			useValue: options,
		},
		UserService, LocalStrategy, JwtStrategy],
	exports: [UserService]
})

@Module(module())

export class UserModule {
	static register(options: UserConfig): DynamicModule {
		return { module: UserModule, ...module(options) };
	}
}
