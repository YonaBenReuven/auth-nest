import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Repository, DeepPartial } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as base64 from 'base-64';

import { User } from './user.entity';
import { Role } from 'src/role/role.entity';
import { RequestUserType } from 'src/common/interfaces/request-user-type.interface';
import { RoleAccessConfig } from 'src/common/interfaces/role-access-config.interface';

@Injectable()
export class UserService {

	roleAccessConfig: RoleAccessConfig;

	constructor(
		@InjectRepository(User)
		private readonly userRepository: Repository<User>,
		private readonly jwtService: JwtService,
	) {
		this.roleAccessConfig = require('../../role-access.config.json');
	}

	createUser(user: DeepPartial<User>) {
		return this.userRepository.save(user);
	}

	async getRolesById(id: string) {
		const roles = await this.userRepository
			.createQueryBuilder('user')
			.relation('roles')
			.of(id)
			.loadMany() as Role[];

		return roles.map(role => role.name);
	}

	matchRoles(userRoles: string[], roles: string[]) {
		return userRoles.some(role => roles.includes(role));
	}

	async matchRolesById(id: string, roles: string[]) {
		const userRoles = await this.getRolesById(id);
		if (!userRoles) return false;

		return this.matchRoles(userRoles, roles);
	}

	getKlos(roles: string[]) {
		const { a, b } = roles
			.map(role => this.roleAccessConfig[role])
			.reduce(({ a }, { components, defaultHomePage }) => {
				return { a: [...a, ...components], b: defaultHomePage };
			}, { a: [], b: '' } as { a: string[]; b: string; });

		const klo = base64.encode(JSON.stringify({ a, b }));

		return klo;
	}

	async getKlosById(id: string) {
		const roles = await this.userRepository
			.createQueryBuilder('user')
			.relation('roles')
			.of(id)
			.loadMany() as Role[];

		const klo = this.getKlos(roles.map(role => role.name));

		return klo;
	}

	async validateUser(username: string, pass: string): Promise<any> {
		const user = await this.userRepository
			.createQueryBuilder('user')
			.addSelect('user.password')
			.leftJoinAndSelect('user.roles', 'role')
			.where({ username })
			.getOne();

		if (!user) return null;
		if (!bcrypt.compareSync(pass, user.password)) return null;

		const requestUser: RequestUserType = {
			id: user.id,
			username: user.username,
			roles: user.roles.map(role => role.name)
		}

		return requestUser;
	}

	async login(user: RequestUserType) {
		const klo = this.getKlos(user.roles);
		return { ...user, klo, access_token: this.jwtService.sign(user) };
	}
}
