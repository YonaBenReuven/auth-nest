import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';

import { User } from './user.entity';

@Injectable()
export class UserService {
	constructor(
		@InjectRepository(User)
		private readonly userRepository: Repository<User>,
		private readonly jwtService: JwtService,
	) { }

	async getUserRoles(id: string) {
		const user = await this.userRepository.findOne(id, { relations: ['roles'] });
		if (!user) return null;
		const roles = user.roles.map(role => role.name);
		return roles;
	}

	matchRoles(userRoles: string[], roles: string[]) {
		return userRoles.some(role => roles.includes(role));
	}

	async matchRolesById(id: string, roles: string[]) {
		const userRoles = await this.getUserRoles(id);
		if (!userRoles) return false;

		return this.matchRoles(userRoles, roles);
	}
}
