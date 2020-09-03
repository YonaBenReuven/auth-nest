import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from '@hilma/auth-nest';

import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { Admin } from './admin.entity';

@Module({
	imports: [TypeOrmModule.forFeature([Admin]), UserModule.register({ maxAge: 44444 })],
	providers: [AdminService],
	controllers: [AdminController]
})
export class AdminModule { }
