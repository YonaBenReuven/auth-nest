import { Module, DynamicModule } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';

import { jwtConstants } from 'src/common/constants';
import { LocalStrategy } from 'src/common/strategies/local.strategy';
import { JwtStrategy } from 'src/common/strategies/jwt.strategy';
import { RoleModule } from 'src/role/role.module';
import { UserService } from './user.service';
import { User } from './user.entity';
import UserConfigOptions from './userConfigOptions';

const userModule = (options: UserConfigOptions = new UserConfigOptions()) => ({
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

@Module(userModule())

export class UserModule {
	static register(options: UserConfigOptions = new UserConfigOptions()): DynamicModule {
		return { module: UserModule, ...userModule(options) };
	}
}