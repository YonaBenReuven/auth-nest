import { Controller, Get, Param, Post } from '@nestjs/common';
import { AppService } from './app.service';
import { UserService } from './user/user.service';
import { UseLocalAuth } from './common/decorators/use-local-auth.decorator';
import { RequestUser } from './common/decorators/request-user.decorator';

@Controller()
export class AppController {
	constructor(
		private readonly appService: AppService,
		private readonly userService: UserService
	) { }

	@UseLocalAuth()
	@Post('login')
	login(@RequestUser() user: any) {
		return this.userService.login(user);
	}

	@Get(':id')
	getRoles(@Param('id') id: string) {
		return this.userService.getUserRoles(id);
	}

	@Get()
	getHello(): string {
		return this.appService.getHello();
	}
}
