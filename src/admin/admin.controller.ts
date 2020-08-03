import { Controller, Post } from '@nestjs/common';

import { Admin } from './admin.entity';
import { RequestUser } from 'src/common/decorators/request-user.decorator';
import { RequestUserType } from 'src/common/interfaces/request-user-type.interface';
import { UserService } from 'src/user/user.service';
import { UseLocalAuth } from 'src/common/decorators/use-local-auth.decorator';

@Controller('admin')
export class AdminController {
	constructor(
		private readonly userService: UserService
	) { }

	@UseLocalAuth(Admin)
	@Post('login')
	login(@RequestUser() user: RequestUserType) {
		return this.userService.login(user);
	}
}