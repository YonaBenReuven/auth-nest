import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as base64 from 'base-64';

import { RoleAccessConfig } from 'src/common/interfaces/role-access-config.interface';

import { User } from './user.entity';

const roleAccessConfig: RoleAccessConfig = require('../../role-access.config.json');

@Injectable()
export class UserService {
	constructor(
		@InjectRepository(User)
		private readonly userRepository: Repository<User>,
		private readonly jwtService: JwtService,
	) { }

	async getUserRoles(id: string) {
		const user = await this.userRepository
			.createQueryBuilder('user')
			.whereInIds([id])
			.leftJoinAndSelect('user.roles', 'role')
			.getOne();

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

	async validateUser(username: string, pass: string): Promise<any> {
		const user = await this.userRepository
			.createQueryBuilder('user')
			.where({ username })
			.leftJoinAndSelect('user.roles', 'role')
			.getOne();

		if (!user) return null;
		if (!bcrypt.compareSync(pass, user.password)) return null;

		const { password, ...result } = user;
		if (user.roles.length === 0) return result;

		const { a, b } = user.roles
			.map(role => roleAccessConfig[role.name])
			.reduce(({ a }, { component, defaultHomePage }) => {
				return { a: [...a, ...component], b: defaultHomePage };
			}, { a: [], b: '' } as { a: string[]; b: string; });

		const klo = base64.encode(JSON.stringify({ a, b }));
		return { ...result, klo };
	}

	async login(user: any) {
		const { klo, ...result } = user;
		return { ...user, access_token: this.jwtService.sign(result) };
	}
}
