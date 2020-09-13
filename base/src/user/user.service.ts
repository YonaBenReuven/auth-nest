import { Injectable, 
	// Inject 
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { Repository, DeepPartial } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as base64 from 'base-64';
import * as randomstring from 'randomstring';

import { User } from './user.entity';
import { Role } from '../role/role.entity';
import { RequestUserType } from '../common/interfaces/request-user-type.interface';
import { RoleAccessConfig } from '../common/interfaces/role-access-config.interface';
import { SALT, 
	// USER_MODULE_OPTIONS 
} from '../common/constants';
// import { UserConfig } from './user.config.interface';

@Injectable()
export class UserService {

	roleAccessConfig: Record<string, RoleAccessConfig>;

	constructor(
		// @Inject(USER_MODULE_OPTIONS) private options: UserConfig,
		@InjectRepository(User)
		private readonly userRepository: Repository<User>,
		private readonly jwtService: JwtService,

	) {
		this.roleAccessConfig = require('../../../../../role-access.config.json');
	}

	createUser(user: DeepPartial<User>) {
		return this.userRepository.save(user);
	}
	/**
	 * Gets a user's roles by its id
	 * @param id The user's id
	 * @returns An array of the user's roles' names
	 */
	async getRolesById(id: string) {
		const roles = await this.userRepository
			.createQueryBuilder('user')
			.relation('roles')
			.of(id)
			.loadMany<Role>();

		return roles.map(role => role.name);
	}
	/**
	 * Matches a user's roles to a given array of roles
	 * @param userRoles The user's roles
	 * @param roles The roles that need to be matched to the user's roles
	 * @returns A boolean that indicates if the roles match, i.e. if some of the user's roles are in the given array
	 */
	matchRoles(userRoles: string[], roles: string[]) {
		return userRoles.some(role => roles.includes(role));
	}
	/**
	 * Matches a user's roles by its id to a given array of roles
	 * @param id The user's id
	 * @param roles The roles that need to be matched to the user's roles
	 * @returns A boolean that indicates if the roles match, i.e. if some of the user's roles are in the given array
	 */
	async matchRolesById(id: string, roles: string[]) {
		const userRoles = await this.getRolesById(id);
		if (!userRoles) return false;

		return this.matchRoles(userRoles, roles);
	}
	/**
	 * Matches a user's type to an array of entities that extend the User entity
	 * @param type The user's type
	 * @param entities An array of entities that extend the User entity
	 * @returns A boolean that indicates if the type matches, i.e. if the entities include the type
	 */
	matchEntities<T extends Array<typeof User>>(type: string, entities: T) {
		return entities.map(entity => entity.name).includes(type);
	}
	/**
	 * Produces a user's klos by its roles
	 * @param roles An array of strings representing a user's roles
	 * @returns A string that is an encoded version of a user's components and default home page
	 */
	getKlos(roles: string[]) {
		const { a, b } = roles
			.map(role => this.roleAccessConfig[role])
			.reduce(({ a }, { components, defaultHomePage }) => {
				return { a: [...a, ...components], b: defaultHomePage };
			}, { a: [], b: '' } as { a: string[]; b: string; });

		const klo = base64.encode(JSON.stringify({ a, b }));

		return klo;
	}
	/**
	 * Produces a user's klos by its id
	 * @param id The user's id
	 * @returns A string that is an encoded version of a user's components and default home page
	 */
	async getKlosById(id: string) {
		const roles = await this.userRepository
			.createQueryBuilder('user')
			.relation('roles')
			.of(id)
			.loadMany() as Role[];

		const klo = this.getKlos(roles.map(role => role.name));

		return klo;
	}
	/**
	 * Validates a user by its username and password
	 * @param username The user's username
	 * @param pass The user's password
	 * @returns If the user's username exists and the password is correct a response is returned consisting of the user's id, username, type, and roles
	 * Otherwise, i.e. if the username doesn't exits or the password is incorrect, null is returned
	 */
	async validateUser(username: string, pass: string) {
		const user = await this.userRepository
			.createQueryBuilder('user')
			.addSelect('user.password')
			.addSelect('user.type')
			.leftJoinAndSelect('user.roles', 'role')
			.where({ username })
			.getOne();

		if (!user) return null;
		if (!bcrypt.compareSync(pass, user.password)) return null;

		const requestUser: RequestUserType = {
			id: user.id,
			username: user.username,
			type: user.type,
			roles: user.roles.map(role => role.name)
		}

		return requestUser;
	}
	/**
	 * Creates a login response for a controller's endpoint
	 * @param user A user request type created by validate user
	 * @param res The response object from the controller's endpoint
	 * @returns A login response consisting of the user request and the cookies that are attached to the response object
	 */
	login(user: RequestUserType, res: Response) {
		const cookies = {
			access_token: this.jwtService.sign(user),
			klo: this.getKlos(user.roles),
			kl: randomstring.generate({ length: 68 }),
			kloo: randomstring.generate({ length: 68 }),
			klk: randomstring.generate({ length: 68 }),
		};

		for (const key in cookies) {
			res.cookie(key, cookies[key as keyof typeof cookies]);
		}

		const body = { ...user, ...cookies };

		return body;
	}

	// With a givan userId, if oldPassword is matching, change to newPassword
	async changePassword(userId: string | number, oldPassword: string, newPassword: string) {
		const user = await this.userRepository
			.createQueryBuilder('user')
			.addSelect('user.password')
			.where({ id: userId })
			.getOne();

		if (!user) return `Could not find user with id ${userId}`;
		if (!bcrypt.compareSync(oldPassword, user.password)) return 'Passwords does not match.';
		return await this.setPassword(userId, newPassword);
	}

	// With a givan userId, change directly to newPassword (usefull for admins, for example)
	async setPassword(userId: string | number, newPassword: string) {
		let password = await bcrypt.hash(newPassword, SALT);
		let updated = await this.userRepository.update(userId, { password })
		console.log("updated", updated)
		return updated;
	}
}
