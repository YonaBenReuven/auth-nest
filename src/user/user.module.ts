import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';

import { jwtConstants  } from 'src/common/constants';
import { LocalStrategy  } from 'src/common/strategies/local.strategy';
import { JwtStrategy  } from 'src/common/strategies/jwt.strategy';
import { RoleModule } from 'src/role/role.module';
import { UserService } from './user.service';
import { User } from './user.entity';

@Module({
	imports: [
		RoleModule,
		TypeOrmModule.forFeature([User]),
		JwtModule.register({
			secret: jwtConstants.secret,
			signOptions: { expiresIn: '100min' },
		})
	],
	providers: [UserService, LocalStrategy, JwtStrategy],
	exports: [UserService]
})
export class UserModule { }
