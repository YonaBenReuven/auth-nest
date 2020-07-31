import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';

import { jwtConstants } from 'src/common/constants';

import { UserService } from './user.service';
import { User } from './user.entity';
import { RoleModule } from 'src/role/role.module';

@Module({
	imports: [
		RoleModule,
		TypeOrmModule.forFeature([User]),
		JwtModule.register({
			secret: jwtConstants.secret,
			signOptions: { expiresIn: '100min' },
		})
	],
	providers: [UserService]
})
export class UserModule { }
