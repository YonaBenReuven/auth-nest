import { Controller, Get, Param } from '@nestjs/common';
import { AppService } from './app.service';
import { UserService } from './user/user.service';

@Controller()
export class AppController {
	constructor(
		private readonly appService: AppService,
		private readonly userService: UserService
		) { }

	@Get(':id')
	getRoles(@Param('id') id: string) {
		return this.userService.getUserRoles(id);
	}

	@Get()
	getHello(): string {
		return this.appService.getHello();
	}
}
