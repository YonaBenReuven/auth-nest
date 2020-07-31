import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { UserRoleService } from './user-role.service';
import { UserRole } from './user-role.entity';

@Module({
	imports: [TypeOrmModule.forFeature([UserRole])],
	providers: [UserRoleService]
})
export class UserRoleModule { }
