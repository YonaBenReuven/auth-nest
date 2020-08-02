import { Controller, Get, Param, Post } from '@nestjs/common';

import { AppService } from './app.service';
import { UserService } from './user/user.service';
import { UseLocalAuth } from './common/decorators/use-local-auth.decorator';
import { RequestUser } from './common/decorators/request-user.decorator';
import { RequestUserType } from './common/interfaces/request-user-type.interface';
import { UseJwtAuth } from './common/decorators/use-jwt-auth.decorator';
import { Admin } from './admin/admin.entity';

@Controller()
export class AppController {
	constructor(
		private readonly appService: AppService,
		private readonly userService: UserService
	) { }

	@UseLocalAuth()
	@Post('login')
	login(@RequestUser() user: RequestUserType) {
		return this.userService.login(user);
	}

	@UseJwtAuth()
	@Get('getStuff')
	getStuff(@RequestUser('id') id: string) {
		console.log(id);
	}

	@Get(':id')
	getRoles(@Param('id') id: string) {
		return this.userService.getRolesById(id);
	}

	@Get()
	getHello(): string {
		return this.appService.getHello();
	}
}
