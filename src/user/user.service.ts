import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { User } from './user.entity';

@Injectable()
export class UserService {
	constructor(
		@InjectRepository(User)
		private readonly userRepository: Repository<User>
	) { }

	async getUserRoles(id: string) {
		const user = await this.userRepository.createQueryBuilder('user')
			.whereInIds([id])
			.leftJoinAndSelect('user.userRole', 'userRole')
			.leftJoinAndSelect('userRole.role', 'role')
			.getOne();

		if (!user) return null;

		const roles = user.userRoles.map(userRole => userRole.role.name);
		
		return roles;
	}

	async matchRolesById(id: string, roles: string[]) {
		const userRoles = await this.getUserRoles(id);
		if (!userRoles) return false;

		return this.matchRoles(userRoles, roles);
	}

	matchRoles(userRoles: string[], roles: string[]) {
		return userRoles.some(role => roles.includes(role));
	}
}
