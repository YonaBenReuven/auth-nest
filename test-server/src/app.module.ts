import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { UserModule, RoleModule } from '@hilma/auth-nest';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AdminModule } from './admin/admin.module';
import configuration from './config/configuration';

@Module({
	imports: [TypeOrmModule.forRoot(), ConfigModule.forRoot({ load: [configuration], isGlobal: true }),
		UserModule, RoleModule, AdminModule],
	controllers: [AppController],
	providers: [AppService],
})
export class AppModule { }
