import { Module } from '@nestjs/common';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { RoleModule } from './role/role.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserRoleModule } from './user-role/user-role.module';

@Module({
	imports: [TypeOrmModule.forRoot(), UserModule, RoleModule, UserRoleModule],
	controllers: [AppController],
	providers: [AppService],
})
export class AppModule { }
