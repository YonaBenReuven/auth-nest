import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { UserPassword } from './user-password.entity';
import { UserPasswordService } from './user-password.service';

@Module({
	imports: [TypeOrmModule.forFeature([UserPassword])],
	providers: [UserPasswordService],
	exports: [UserPasswordService]
})
export class UserPasswordModule { }
